#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include "netloader.h"
#include "usb.h"

#define USB_SERIAL_INTERFACE 0
#define USB_SERIAL_EP_IN 0
#define USB_SERIAL_EP_OUT 1

static mtx_t netloader_mtx;

static menuEntry_s netloader_me;
static volatile bool netloader_initialized = 0;
static volatile bool netloader_exitflag = 0;
static volatile bool netloader_activated = 0, netloader_launchapp = 0;
static volatile size_t netloader_filelen = 0, netloader_filetotal = 0;
static volatile char netloader_errortext[1024];
static volatile bool netloader_connected = 0;

static bool netloaderGetExit(void);

//---------------------------------------------------------------------------------
static Result usbSerialInit(void)
//---------------------------------------------------------------------------------
{
    UsbInterfaceDesc info;

    struct usb_device_descriptor device_descriptor = {
        .bLength = USB_DT_DEVICE_SIZE,
        .bDescriptorType = USB_DT_DEVICE,
        .bcdUSB = 0x0110,
        .bDeviceClass = 0x00,
        .bDeviceSubClass = 0x00,
        .bDeviceProtocol = 0x00,
        .bMaxPacketSize0 = 0x40,
        .idVendor = 0x057e,
        .idProduct = 0x3000,
        .bcdDevice = 0x0100,
        .bNumConfigurations = 0x01
    };

    struct usb_interface_descriptor serial_interface_descriptor = {
        .bLength = USB_DT_INTERFACE_SIZE,
        .bDescriptorType = USB_DT_INTERFACE,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
        .bInterfaceSubClass = USB_CLASS_VENDOR_SPEC,
        .bInterfaceProtocol = USB_CLASS_VENDOR_SPEC,
    };

    struct usb_endpoint_descriptor serial_endpoint_descriptor_in = {
       .bLength = USB_DT_ENDPOINT_SIZE,
       .bDescriptorType = USB_DT_ENDPOINT,
       .bEndpointAddress = USB_ENDPOINT_IN,
       .bmAttributes = USB_TRANSFER_TYPE_BULK,
       .wMaxPacketSize = 0x200,
    };

    struct usb_endpoint_descriptor serial_endpoint_descriptor_out = {
       .bLength = USB_DT_ENDPOINT_SIZE,
       .bDescriptorType = USB_DT_ENDPOINT,
       .bEndpointAddress = USB_ENDPOINT_OUT,
       .bmAttributes = USB_TRANSFER_TYPE_BULK,
       .wMaxPacketSize = 0x200,
    };

    info.interface_desc = &serial_interface_descriptor;
    info.endpoint_desc[USB_SERIAL_EP_IN] = &serial_endpoint_descriptor_in;
    info.endpoint_desc[USB_SERIAL_EP_OUT] = &serial_endpoint_descriptor_out;
    info.string_descriptor = NULL;

    return usbInitialize(&device_descriptor, 1, &info);
}

//---------------------------------------------------------------------------------
ssize_t usbSerialRead(char *ptr, size_t len)
//---------------------------------------------------------------------------------
{
    return usbTransfer(USB_SERIAL_INTERFACE, USB_SERIAL_EP_OUT, UsbDirection_Read, (void*)ptr, len, 1000000000LL);
}

//---------------------------------------------------------------------------------
ssize_t usbSerialWrite(const char *ptr, size_t len)
//---------------------------------------------------------------------------------
{
    return usbTransfer(USB_SERIAL_INTERFACE, USB_SERIAL_EP_IN, UsbDirection_Write, (void*)ptr, len, U64_MAX);
}

//---------------------------------------------------------------------------------
static void netloader_error(const char *func, int err) {
//---------------------------------------------------------------------------------
    if (!netloader_initialized || netloaderGetExit()) return;

    mtx_lock(&netloader_mtx);
    if (netloader_errortext[0] == 0) {
        memset((char*)netloader_errortext, 0, sizeof(netloader_errortext));
        snprintf((char*)netloader_errortext, sizeof(netloader_errortext)-1, "%s: err=%d\n %s\n", func, err, strerror(errno));
    }
    mtx_unlock(&netloader_mtx);
}

static const char DIRECTORY_THIS[] = ".";
static const char DIRECTORY_PARENT[] = "..";

//---------------------------------------------------------------------------------
static bool isDirectorySeparator(int c) {
//---------------------------------------------------------------------------------
    return c == DIRECTORY_SEPARATOR_CHAR;
}

//---------------------------------------------------------------------------------
static void sanitisePath(char *path) {
//---------------------------------------------------------------------------------
    char *tmpPath = strdup(path);
    tmpPath[0] = 0;

    char *dirStart = path;
    char *curPath = tmpPath;

    dirStart = path;

    while(isDirectorySeparator(dirStart[0])) dirStart++;

    do {
        char *dirEnd = strchr(dirStart, DIRECTORY_SEPARATOR_CHAR);
        if (dirEnd) {
            dirEnd++;
            if(!strncmp(DIRECTORY_PARENT,dirStart,strlen(DIRECTORY_PARENT))) {
                /* move back one directory */
                size_t pathlen = strlen(tmpPath);
                if(tmpPath[pathlen-1] == DIRECTORY_SEPARATOR_CHAR) tmpPath[pathlen-1] = 0;
                char *prev = strrchr(tmpPath,DIRECTORY_SEPARATOR_CHAR);
                if (prev) {
                    curPath = prev + 1;
                } else {
                    curPath = tmpPath;
                }


                dirStart = dirEnd;
            } else if (!strncmp(DIRECTORY_THIS,dirStart,strlen(DIRECTORY_THIS))) {
                /* strip this entry */
                dirStart = dirEnd;
            } else {
                size_t dirSize = dirEnd - dirStart;
                strncpy(curPath,dirStart,dirSize);
                curPath[dirSize] = 0;
                curPath += dirSize;
                dirStart += dirSize;
            }
        } else {
            strcpy(curPath,dirStart);
            dirStart += strlen(dirStart);
        }
    } while(dirStart[0]);

    strcpy(path, tmpPath);
    free(tmpPath);
}

//---------------------------------------------------------------------------------
int loadnro(menuEntry_s *me) {
//---------------------------------------------------------------------------------
    int len, namelen, filelen;
    char filename[PATH_MAX+1];
    len = usbSerialRead((char*)&namelen, 4);

    if (len != 4) {
        netloader_error("Error getting name length", errno);
        return -1;
    }

    if (namelen >= sizeof(filename)-1) {
        netloader_error("Filename length is too large",errno);
        return -1;
    }

    len = usbSerialRead(filename, namelen);

    if (len != namelen) {
        netloader_error("Error getting filename", errno);
        return -1;
    }

    filename[namelen] = 0;

    len = usbSerialRead((char*)&filelen, 4);

    if (len != 4) {
        netloader_error("Error getting file length",errno);
        return -1;
    }

    mtx_lock(&netloader_mtx);
    netloader_filelen = filelen;
    mtx_unlock(&netloader_mtx);

    int response = 0;

    sanitisePath(filename);

    snprintf(me->path, sizeof(me->path)-1, "%s%s%s", menuGetRootPath(), DIRECTORY_SEPARATOR,  filename);
    me->path[PATH_MAX] = 0;
    // make sure it's terminated
    me->path[PATH_MAX] = 0;

    argData_s* ad = &me->args;
    ad->dst = (char*)&ad->buf[1];
    //ad->nxlink_host = 0;

    launchAddArg(ad, me->path);

    int fd = open(me->path,O_CREAT|O_WRONLY, ACCESSPERMS);

    if (fd < 0) {
        response = -1;
        netloader_error("open", errno);
    } else {
        if (ftruncate(fd,filelen) == -1) {
            response = -2;
            netloader_error("ftruncate",errno);
        }
        close(fd);
    }

    FILE *file = NULL;

    if (response == 0)
        file = fopen(me->path,"wb");

    if(NULL == file) {
        perror("file");
        response = -1;
    }

    usbSerialWrite((char *)&response,sizeof(response));

    char *writebuffer = NULL;
    if (response == 0 ) {
        writebuffer = (char*)memalign(0x1000, 16384);
        if (writebuffer==NULL) {
            netloader_error("Failed to allocate memory",ENOMEM);
            response = -1;
        }
        else
            setvbuf(file,writebuffer,_IOFBF, 16384);
    }

    if (response == 0 ) {
        // TODO: Add back zlib compression
        while(netloader_filetotal != netloader_filelen && !netloaderGetExit())
        {
            len = usbSerialRead(writebuffer, 16384);

            if(len < 0)
                break;

            fwrite(writebuffer, 1, len, file);
            netloader_filetotal += len;
        }

        if(netloader_filetotal != netloader_filelen)
            response = -1;
        
        usbSerialWrite((char *)&response,sizeof(response));

        // Command line
        int netloaded_cmdlen = 0;
        if (response == 0 ) {
            len = usbSerialRead((char*)&netloaded_cmdlen,4);
        
            if (len != 4) {
                netloader_error("Error getting netloaded_cmdlen",errno);
                response = -1;
            }
        }
        
        if (response == 0 ) {
            if (netloaded_cmdlen > sizeof(me->args.buf)-1) netloaded_cmdlen = sizeof(me->args.buf)-1;
        
            len = usbSerialRead(me->args.dst, netloaded_cmdlen);
        
            if (len != netloaded_cmdlen) {
                netloader_error("Error getting args",errno);
                response = -1;
            }
        }
        
        if (response == 0 ) {
            while(netloaded_cmdlen) {
                size_t len = strlen(me->args.dst) + 1;
                ad->dst += len;
                ad->buf[0]++;
                netloaded_cmdlen -= len;
            }
        }

        fflush(file);
        fclose(file);
        free(writebuffer);

        if (response == -1) unlink(me->path);
    }

    return response;
}

static int netloader_connect(void) {
    char start[7];
    usbSerialRead(start, 7);

    if(strcmp(start, "#START#") != 0)
        return 0;

    mtx_lock(&netloader_mtx);
    netloader_connected = 1;
    mtx_unlock(&netloader_mtx);
    return 1;
}

static void netloader_disconnect(void) {
    const char* stop = "#STOP#";

    if(netloader_connected == 0)
        return;

    usbSerialWrite(stop, 6);
    mtx_lock(&netloader_mtx);
    netloader_connected = 0;
    mtx_unlock(&netloader_mtx);
}

void netloaderGetState(netloaderState *state) {
    if(state==NULL)return;
    mtx_lock(&netloader_mtx);

    state->activated = netloader_activated;
    state->launch_app = netloader_launchapp;
    state->me = &netloader_me;

    state->transferring = netloader_filelen;
    state->sock_connected = netloader_connected;
    state->filelen = netloader_filelen;
    state->filetotal = netloader_filetotal;

    memset(state->errormsg, 0, sizeof(state->errormsg));
    if(netloader_errortext[0]) {
        strncpy(state->errormsg, (char*)netloader_errortext, sizeof(state->errormsg)-1);
        memset((char*)netloader_errortext, 0, sizeof(netloader_errortext));
    }

    mtx_unlock(&netloader_mtx);
}

static bool netloaderGetExit(void) {
    bool flag;
    mtx_lock(&netloader_mtx);
    flag = netloader_exitflag;
    mtx_unlock(&netloader_mtx);
    return flag;
}

void netloaderSignalExit(void) {
    if (!netloader_initialized) return;

    mtx_lock(&netloader_mtx);
    netloader_exitflag = 1;
    mtx_unlock(&netloader_mtx);
}

Result netloaderInit(void) {
    Result rc=0;
    if (netloader_initialized) return 0;

    if (mtx_init(&netloader_mtx, mtx_plain) != thrd_success) return 1;

    rc = usbSerialInit();

    if (rc) {
        mtx_destroy(&netloader_mtx);
        return rc;
    }

    netloader_initialized = 1;
    return 0;
}

void netloaderExit(void) {
    if (!netloader_initialized) return;
    netloader_initialized = 0;

    mtx_destroy(&netloader_mtx);

    usbExit();
}

void netloaderTask(void* arg) {
    int ret=0;
    struct timespec duration = {.tv_nsec = 100000000};
    menuEntryInit(&netloader_me,ENTRY_TYPE_FILE);

    mtx_lock(&netloader_mtx);
    netloader_exitflag = 0;
    netloader_activated = 0;
    netloader_launchapp = 0;
    netloader_filelen = 0;
    netloader_filetotal = 0;
    netloader_connected = 0;
    netloader_activated = 1;
    mtx_unlock(&netloader_mtx);

    while(!netloader_connect() && !netloaderGetExit()) {
        thrd_sleep(&duration, NULL);
    }

    if(!netloaderGetExit()) {
        int result = loadnro(&netloader_me);
        if (result== 0) {
            ret = 1;
        } else {
            ret = -1;
        }
    }

    netloader_disconnect();
    mtx_lock(&netloader_mtx);
    if (ret==1 && !netloader_exitflag) netloader_launchapp = 1;//Access netloader_exitflag directly since the mutex is already locked.
    netloader_exitflag = 0;
    netloader_activated = 0;
    mtx_unlock(&netloader_mtx);
}

