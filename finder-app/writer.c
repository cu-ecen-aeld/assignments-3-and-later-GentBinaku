#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
  // Open a connection to the syslog
  openlog("writer", LOG_PID, LOG_USER);

  if (argc != 3) {
    syslog(LOG_ERR,
           "Error: Two arguments required. Usage: %s <file_path> <text_string>",
           argv[0]);
    fprintf(
        stderr,
        "Error: Two arguments required. Usage: %s <file_path> <text_string>\n",
        argv[0]);
    closelog();
    return 1;
  }

  const char *writefile = argv[1];
  const char *writestr = argv[2];

  // Write the content to the file, overwriting if it exists
  FILE *file = fopen(writefile, "w");
  if (file == NULL) {
    syslog(LOG_ERR, "Error: Could not create or write to file '%s'", writefile);
    perror("fopen");
    closelog();
    return 1;
  }

  if (fprintf(file, "%s", writestr) < 0) {
    syslog(LOG_ERR, "Error: Could not write to file '%s'", writefile);
    perror("fprintf");
    fclose(file);
    closelog();
    return 1;
  }

  fclose(file);
  syslog(LOG_DEBUG, "Writing '%s' to '%s'", writestr, writefile);
  printf("File '%s' created successfully with content: '%s'\n", writefile,
         writestr);

  // Close the connection to the syslog
  closelog();
  return 0;
}
