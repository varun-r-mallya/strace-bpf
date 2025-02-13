#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

int main() {
    const char *filename = "/tmp/testfile.txt";
    int fd;
    //output self PID
    printf("PID: %d\n", getpid());

    while (1) {
        fd = open(filename, O_CREAT | O_WRONLY, 0644);
        if (fd == -1) {
            perror("open");
            return 1;
        }
        printf("File opened: %s\n", filename);
        close(fd);
        sleep(2);
    }

    return 0;
}