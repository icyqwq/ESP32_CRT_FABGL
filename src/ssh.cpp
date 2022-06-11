#include "ssh.h"
#include "fabgl.h"

extern fabgl::LineEditor LineEditor;

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    char buf[10];
    unsigned char *hash = NULL;
    size_t hlen;
    ssh_key srv_pubkey;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0)
    {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA256,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0)
    {
        return -1;
    }

    state = ssh_session_is_known_server(session);

    switch (state)
    {
    case SSH_KNOWN_HOSTS_CHANGED:
        fprintf(stderr, "Host key for server changed : server's one is now :\r\n");
        ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
        fprintf(stderr,"\r");
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr, "For security reason, connection will be stopped\r\n");
        return -1;
    case SSH_KNOWN_HOSTS_OTHER:
        fprintf(stderr, "The host key for this server was not found but an other type of key exists.\r\n");
        fprintf(stderr, "An attacker might change the default server key to confuse your client"
                        "into thinking the key does not exist\r\n"
                        "We advise you to rerun the client with -d or -r for more safety.\r\n");
        return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
        fprintf(stderr, "Could not find known host file. If you accept the host key here,\r\n");
        fprintf(stderr, "the file will be automatically created.\r\n");
        /* fallback to SSH_SERVER_NOT_KNOWN behavior */
        FALL_THROUGH;
    case SSH_SERVER_NOT_KNOWN:
        fprintf(stderr,
                "The server is unknown. Do you trust the host key (yes/no)?\r\n");
        ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
        fprintf(stderr,"\r");

        LineEditor.setText("");
        LineEditor.edit();

        if (strncasecmp(LineEditor.get(), "yes", 3) != 0)
        {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        fprintf(stderr, "This new key will be written on disk for further usage. do you agree (yes/no)?\r\n");

        LineEditor.setText("");
        LineEditor.edit();

        if (strncasecmp(LineEditor.get(), "yes", 3) == 0)
        {
            rc = ssh_session_update_known_hosts(session);
            if (rc != SSH_OK)
            {
                ssh_clean_pubkey_hash(&hash);
                fprintf(stderr, "error %s\r\n", strerror(errno));
                return -1;
            }
        }

        break;
    case SSH_KNOWN_HOSTS_ERROR:
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr, "%s", ssh_get_error(session));
        return -1;
    case SSH_KNOWN_HOSTS_OK:
        break; /* ok */
    }

    ssh_clean_pubkey_hash(&hash);

    return 0;
}

int authenticate_kbdint(ssh_session session, const char *password)
{
    int err;

    err = ssh_userauth_kbdint(session, NULL, NULL);
    while (err == SSH_AUTH_INFO)
    {
        const char *instruction;
        const char *name;
        char buffer[128];
        int i, n;

        name = ssh_userauth_kbdint_getname(session);
        instruction = ssh_userauth_kbdint_getinstruction(session);
        n = ssh_userauth_kbdint_getnprompts(session);

        if (name && strlen(name) > 0)
        {
            printf("%s\r\n", name);
        }

        if (instruction && strlen(instruction) > 0)
        {
            printf("%s\r\n", instruction);
        }

        for (i = 0; i < n; i++)
        {
            const char *answer;
            const char *prompt;
            char echo;

            prompt = ssh_userauth_kbdint_getprompt(session, i, &echo);
            if (prompt == NULL)
            {
                break;
            }

            if (echo)
            {
                char *p;

                printf("%s", prompt);

                if (fgets(buffer, sizeof(buffer), stdin) == NULL)
                {
                    return SSH_AUTH_ERROR;
                }

                buffer[sizeof(buffer) - 1] = '\0';
                if ((p = strchr(buffer, '\r\n')))
                {
                    *p = '\0';
                }

                if (ssh_userauth_kbdint_setanswer(session, i, buffer) < 0)
                {
                    return SSH_AUTH_ERROR;
                }

                memset(buffer, 0, strlen(buffer));
            }
            else
            {
                if (password && strstr(prompt, "Password:"))
                {
                    answer = password;
                }
                else
                {
                    buffer[0] = '\0';

                    if (ssh_getpass(prompt, buffer, sizeof(buffer), 0, 0) < 0)
                    {
                        return SSH_AUTH_ERROR;
                    }
                    answer = buffer;
                }
                err = ssh_userauth_kbdint_setanswer(session, i, answer);
                memset(buffer, 0, sizeof(buffer));
                if (err < 0)
                {
                    return SSH_AUTH_ERROR;
                }
            }
        }
        err = ssh_userauth_kbdint(session, NULL, NULL);
    }

    return err;
}

static int auth_keyfile(ssh_session session, const char *keyfile)
{
    ssh_key key = NULL;
    char pubkey[132] = {0}; // +".pub"
    int rc;

    snprintf(pubkey, sizeof(pubkey), "%s.pub", keyfile);

    rc = ssh_pki_import_pubkey_file(pubkey, &key);

    if (rc != SSH_OK)
        return SSH_AUTH_DENIED;

    rc = ssh_userauth_try_publickey(session, NULL, key);

    ssh_key_free(key);

    if (rc != SSH_AUTH_SUCCESS)
        return SSH_AUTH_DENIED;

    rc = ssh_pki_import_privkey_file(keyfile, NULL, NULL, NULL, &key);

    if (rc != SSH_OK)
        return SSH_AUTH_DENIED;

    rc = ssh_userauth_publickey(session, NULL, key);
    ssh_key_free(key);

    return rc;
}

static void error(ssh_session session)
{
    fprintf(stderr, "Authentication failed: %s\r\n", ssh_get_error(session));
}

int authenticate_console(ssh_session session)
{
    int rc;
    int method;
    char password[128] = {0};
    char *banner;

    // Try to authenticate
    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_AUTH_ERROR)
    {
        error(session);
        return rc;
    }

    method = ssh_userauth_list(session, NULL);
    while (rc != SSH_AUTH_SUCCESS)
    {
        if (method & SSH_AUTH_METHOD_GSSAPI_MIC)
        {
            rc = ssh_userauth_gssapi(session);
            if (rc == SSH_AUTH_ERROR)
            {
                error(session);
                return rc;
            }
            else if (rc == SSH_AUTH_SUCCESS)
            {
                break;
            }
        }
        // Try to authenticate with public key first
        if (method & SSH_AUTH_METHOD_PUBLICKEY)
        {
            rc = ssh_userauth_publickey_auto(session, NULL, NULL);
            if (rc == SSH_AUTH_ERROR)
            {
                error(session);
                return rc;
            }
            else if (rc == SSH_AUTH_SUCCESS)
            {
                break;
            }
        }
        else
        {
            char *p = NULL;

            printf("Automatic pubkey failed. "
                   "Do you want to try a specific key? (yes/no)\r\n");
            LineEditor.setText("");
            LineEditor.edit();

            if (strncasecmp(LineEditor.get(), "yes", 3) == 0)
            {
                printf("private key filename: ");

                LineEditor.setText("");
                LineEditor.edit();
                auto buffer = LineEditor.get();

                if ((p = strchr(buffer, '\r\n')))
                {
                    *p = '\0';
                }

                rc = auth_keyfile(session, buffer);

                if (rc == SSH_AUTH_SUCCESS)
                {
                    break;
                }
                fprintf(stderr, "failed with key\r\n");
            }
            else
            {
                break;
            }
        }

        // Try to authenticate with keyboard interactive";
        if (method & SSH_AUTH_METHOD_INTERACTIVE)
        {
            rc = authenticate_kbdint(session, NULL);
            if (rc == SSH_AUTH_ERROR)
            {
                error(session);
                return rc;
            }
            else if (rc == SSH_AUTH_SUCCESS)
            {
                break;
            }
        }

        rc = ssh_getpass("Password: ", password, sizeof(password), 0, 0);
        if (rc < 0)
        {
            log_d("rc = %d", rc);
            return SSH_AUTH_ERROR;
        }

        // fprintf(stderr, "\r\nPassword:\r\n");
        // if (fgets(password, sizeof(password), stdin) == NULL)
        // {
        //     return SSH_AUTH_ERROR;
        // }

        // Try to authenticate with password
        if (method & SSH_AUTH_METHOD_PASSWORD)
        {
            rc = ssh_userauth_password(session, NULL, password);

            if (rc == SSH_AUTH_ERROR)
            {
                error(session);
                return rc;
            }
            else if (rc == SSH_AUTH_SUCCESS)
            {
                break;
            }
        }
        memset(password, 0, sizeof(password));
    }

    banner = ssh_get_issue_banner(session);
    if (banner)
    {
        printf("%s\r\n", banner);
        SSH_STRING_FREE_CHAR(banner);
    }

    return rc;
}

ssh_session connect_ssh(const char *host, const char *user, int port, int verbosity)
{
    ssh_session session;
    int auth = 0;

    session = ssh_new();
    if (session == NULL)
    {
        return NULL;
    }

    if (user != NULL)
    {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)
        {
            ssh_free(session);
            return NULL;
        }
    }

    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0)
    {
        ssh_free(session);
        return NULL;
    }
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    if (ssh_connect(session))
    {
        fprintf(stderr, "Connection failed : %s\r\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }
    if (verify_knownhost(session) < 0)
    {
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }
    auth = authenticate_console(session);
    if (auth == SSH_AUTH_SUCCESS)
    {
        return session;
    }
    else if (auth == SSH_AUTH_DENIED)
    {
        fprintf(stderr, "Authentication failed\r\n");
    }
    else
    {
        fprintf(stderr, "Error while authenticating : %s\r\n", ssh_get_error(session));
    }
    ssh_disconnect(session);
    ssh_free(session);
    return NULL;
}