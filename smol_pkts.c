/**
 * @Author: S. Sharma <m4rtyr>
 * @Date:   2020-01-24T20:24:44-06:00
 * @Email:  silentcat@protonmail.com
 * @Last modified by:   m4rtyr
 * @Last modified time: 2020-01-26T21:59:20-06:00
 */

#include "pkt.h"
#include "args.h"
#include <signal.h>

void handle_sig(int sig);
void handle_sig(int sig)
{
  if (sock != -1)
    close(sock);
  if (buff)
    free(buff);
  debug("Freed all resources");
}

int main(int argc, char *argv[])
{
  char *device_name = NULL;
  if (argc > 2) {
    for (int i = 1; i < argc-1; i++) {
      PROCESS_ARG("-i", device_name);
    }
  }
  signal(SIGINT, handle_sig);
  event_loop(device_name);
  return 0;
}
