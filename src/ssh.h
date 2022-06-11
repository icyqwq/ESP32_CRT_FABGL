#ifndef SSH_H
#define SSH_H


#include "libssh_esp32.h"

#include <libssh/libssh.h>
#include "examples_common.h"
#include "IPv6Address.h"
#include "SPIFFS.h"
#include "driver/uart.h"
#include "esp_vfs_dev.h"
#include "libssh_esp32_config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh/priv.h"
#include <regex>

int verify_knownhost(ssh_session session);
int authenticate_kbdint(ssh_session session, const char *password);
static int auth_keyfile(ssh_session session, char *keyfile);
int authenticate_console(ssh_session session);
ssh_session connect_ssh(const char *host, const char *user, int port, int verbosity);

#endif