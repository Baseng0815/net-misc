#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>

struct ioctl_data {
    int a;
    int b;
};

#define MY_IOCTL_IN _IOC(_IOC_WRITE, 'k', 1, sizeof(struct ioctl_data))

int main(int argc, char *argv[])
{
    struct ioctl_data data = {
        .a = 69,
        .b = -1337
    };

    int fd = open("/dev/nsufw", O_RDWR);
    printf("fd=%d\n", fd);
    if (ioctl(fd, MY_IOCTL_IN, &data) < 0) {
        printf("error\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
