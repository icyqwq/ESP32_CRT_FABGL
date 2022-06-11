/*
  Created by Fabrizio Di Vittorio (fdivitto2013@gmail.com) - <http://www.fabgl.com>
  Copyright (c) 2019-2021 Fabrizio Di Vittorio.
  All rights reserved.


* Please contact fdivitto2013@gmail.com if you need a commercial license.


* This library and related software is available under GPL v3.

  FabGL is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  FabGL is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with FabGL.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "fabgl.h"

#include <WiFi.h>

#include "network/ICMP.h"

#include "ssh.h"

#define SSH_MAX_BUFFER_SIZE 4096

const unsigned int configSTACK = 51200;
// Networking state of this esp32 device.
typedef enum
{
    STATE_NEW,
    STATE_PHY_CONNECTED,
    STATE_WAIT_IPADDR,
    STATE_GOT_IPADDR,
    STATE_OTA_UPDATING,
    STATE_OTA_COMPLETE,
    STATE_LISTENING,
    STATE_TCP_DISCONNECTED
} devState_t;

static volatile devState_t devState;
static volatile bool gotIpAddr, gotIp6Addr;

//自动执行的指令
char const *AUTOEXEC =  "info\r"
                        "keyb us\r"
                        // "wifi WIFINAME PASSWORD\r"
                        // "ssh IP_ADDR PORT USER\r"
                        ;

enum class State
{
    Prompt,
    PromptInput,
    UnknownCommand,
    SSHStart,
    SSHRunning,
    SSHInit,
    SSH,
    Help,
    Info,
    Wifi,
    TelnetInit,
    Telnet,
    Scan,
    Ping,
    Reset,
    Keyb
};

State state = State::Prompt;
WiFiClient client;
char const *currentScript = nullptr;
bool error = false;

fabgl::VGATextController DisplayController;
fabgl::PS2Controller PS2Controller;
fabgl::Terminal Terminal;
fabgl::LineEditor LineEditor(&Terminal);

ssh_session session;
ssh_channel channel;

void exe_info()
{
    Terminal.write("\e[97m* * FabGL - Network VT/ANSI Terminal\r\n");
    Terminal.write("\e[94m* * 2019-2021 by Fabrizio Di Vittorio - www.fabgl.com\e[92m\r\n\n");
    Terminal.printf("\e[92mScreen Size        :\e[93m %d x %d\r\n", DisplayController.getScreenWidth(), DisplayController.getScreenHeight());
    Terminal.printf("\e[92mTerminal Size      :\e[93m %d x %d\r\n", Terminal.getColumns(), Terminal.getRows());
    Terminal.printf("\e[92mFree DMA Memory    :\e[93m %d\r\n", heap_caps_get_free_size(MALLOC_CAP_DMA));
    Terminal.printf("\e[92mFree 32 bit Memory :\e[93m %d\r\n", heap_caps_get_free_size(MALLOC_CAP_32BIT));
    if (WiFi.status() == WL_CONNECTED)
    {
        Terminal.printf("\e[92mWiFi SSID          :\e[93m %s\r\n", WiFi.SSID().c_str());
        Terminal.printf("\e[92mCurrent IP         :\e[93m %s\r\n", WiFi.localIP().toString().c_str());
    }
    Terminal.write("\n\e[92mType \e[93mhelp\e[92m to print all available commands.\r\n");
    error = false;
    state = State::Prompt;
}

void exe_help()
{
    Terminal.write("\e[93mhelp\e[92m\r\n");
    Terminal.write("\e[97m  Shows this help.\r\n");
    Terminal.write("\e[93minfo\r\n");
    Terminal.write("\e[97m  Shows system info.\r\n");
    Terminal.write("\e[93mscan\r\n");
    Terminal.write("\e[97m  Scan for WiFi networks.\r\n");
    Terminal.write("\e[93mwifi [SSID PASSWORD]\r\n");
    Terminal.write("\e[97m  Connect to SSID using PASSWORD.\r\n");
    Terminal.write("\e[97m  Example:\r\n");
    Terminal.write("\e[97m    wifi MyWifi MyPassword\r\n");
    Terminal.write("\e[93mtelnet HOST [PORT]\r\n");
    Terminal.write("\e[97m  Open telnet session with HOST (IP or host name) using PORT.\r\n");
    Terminal.write("\e[97m  Example:\r\n");
    Terminal.write("\e[97m    telnet 127.0.0.1\e[92m\r\n");
    Terminal.write("\e[93mssh HOST PORT USER\r\n");
    Terminal.write("\e[97m  Open ssh session with HOST (IP or host name) using PORT.\r\n");
    Terminal.write("\e[97m  Example:\r\n");
    Terminal.write("\e[97m    ssh 127.0.0.1 22 root\e[92m\r\n");
    Terminal.write("\e[93mping HOST\r\n");
    Terminal.write("\e[97m  Ping a HOST (IP or host name).\r\n");
    Terminal.write("\e[97m  Example:\r\n");
    Terminal.write("\e[97m    ping 8.8.8.8\e[92m\r\n");
    Terminal.write("\e[93mreboot\r\n");
    Terminal.write("\e[97m  Restart the system.\e[92m\r\n");
    Terminal.write("\e[93mkeyb LAYOUT\r\n");
    Terminal.write("\e[97m  Set keyboard layout. LAYOUT can be 'us', 'uk', 'de', 'it', 'es', 'fr', 'be'\r\n");
    Terminal.write("\e[97m  Example:\r\n");
    Terminal.write("\e[97m    keyb de\e[92m\r\n");
    error = false;
    state = State::Prompt;
}

void decode_command()
{
    auto inputLine = LineEditor.get();
    if (*inputLine == 0)
        state = State::Prompt;
    else if (strncmp(inputLine, "help", 4) == 0)
        state = State::Help;
    else if (strncmp(inputLine, "ssh", 3) == 0)
        state = State::SSHStart;
    else if (strncmp(inputLine, "info", 4) == 0)
        state = State::Info;
    else if (strncmp(inputLine, "wifi", 4) == 0)
        state = State::Wifi;
    else if (strncmp(inputLine, "telnet", 6) == 0)
        state = State::TelnetInit;
    else if (strncmp(inputLine, "scan", 4) == 0)
        state = State::Scan;
    else if (strncmp(inputLine, "ping", 4) == 0)
        state = State::Ping;
    else if (strncmp(inputLine, "reboot", 6) == 0)
        state = State::Reset;
    else if (strncmp(inputLine, "keyb", 4) == 0)
        state = State::Keyb;
    else
        state = State::UnknownCommand;
}

void exe_prompt()
{
    if (currentScript)
    {
        // process commands from script
        if (*currentScript == 0 || error)
        {
            // end of script, return to prompt
            currentScript = nullptr;
            state = State::Prompt;
        }
        else
        {
            // execute current line and move to the next one
            int linelen = strchr(currentScript, '\r') - currentScript;
            LineEditor.setText(currentScript, linelen);
            currentScript += linelen + 1;
            decode_command();
        }
    }
    else
    {
        // process commands from keyboard
        Terminal.write(">");
        state = State::PromptInput;
    }
}

void exe_promptInput()
{
    LineEditor.setText("");
    LineEditor.edit();
    decode_command();
}

void exe_scan()
{
    static char const *ENC2STR[] = {"Open", "WEP", "WPA-PSK", "WPA2-PSK", "WPA/WPA2-PSK", "WPA-ENTERPRISE"};
    Terminal.write("Scanning...");
    Terminal.flush();
    int networksCount = WiFi.scanNetworks();
    Terminal.printf("%d network(s) found\r\n", networksCount);
    if (networksCount)
    {
        Terminal.write("\e[90m #\e[4GSSID\e[45GRSSI\e[55GCh\e[60GEncryption\e[92m\r\n");
        for (int i = 0; i < networksCount; ++i)
            Terminal.printf("\e[93m %d\e[4G%s\e[93m\e[45G%d dBm\e[55G%d\e[60G%s\e[92m\r\n", i + 1, WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i), ENC2STR[WiFi.encryptionType(i)]);
    }
    WiFi.scanDelete();
    error = false;
    state = State::Prompt;
}

void exe_wifi()
{
    static const int MAX_SSID_SIZE = 32;
    static const int MAX_PSW_SIZE = 32;
    char ssid[MAX_SSID_SIZE + 1];
    char psw[MAX_PSW_SIZE + 1] = {0};
    error = true;
    auto inputLine = LineEditor.get();
    if (sscanf(inputLine, "wifi %32s %32s", ssid, psw) >= 1)
    {
        Terminal.write("Connecting WiFi...");
        Terminal.flush();
        WiFi.disconnect(true, true);
        for (int i = 0; i < 2; ++i)
        {
            WiFi.begin(ssid, psw);
            if (WiFi.waitForConnectResult() == WL_CONNECTED)
                break;
            WiFi.disconnect(true, true);
        }
        if (WiFi.status() == WL_CONNECTED)
        {
            Terminal.printf("connected to %s, IP is %s\r\n", WiFi.SSID().c_str(), WiFi.localIP().toString().c_str());
            error = false;
        }
        else
        {
            Terminal.write("failed!\r\n");
        }
    }
    state = State::Prompt;
}

void exe_telnetInit()
{
    static const int MAX_HOST_SIZE = 32;
    char host[MAX_HOST_SIZE + 1];
    int port;
    error = true;
    auto inputLine = LineEditor.get();
    int pCount = sscanf(inputLine, "telnet %32s %d", host, &port);
    if (pCount > 0)
    {
        if (pCount == 1)
            port = 23;
        Terminal.printf("Trying %s...\r\n", host);
        if (client.connect(host, port))
        {
            Terminal.printf("Connected to %s\r\n", host);
            error = false;
            state = State::Telnet;
        }
        else
        {
            Terminal.write("Unable to connect to remote host\r\n");
            state = State::Prompt;
        }
    }
    else
    {
        Terminal.write("Mistake\r\n");
        state = State::Prompt;
    }
}

int clientWaitForChar()
{
    // not so good...:-)
    while (!client.available())
        ;
    return client.read();
}

void exe_telnet()
{
    // process data from remote host (up to 1024 codes at the time)
    for (int i = 0; client.available() && i < 1024; ++i)
    {
        int c = client.read();
        if (c == 0xFF)
        {
            // IAC (Interpret As Command)
            uint8_t cmd = clientWaitForChar();
            uint8_t opt = clientWaitForChar();
            if (cmd == 0xFD && opt == 0x1F)
            {
                // DO WINDOWSIZE
                client.write("\xFF\xFB\x1F", 3); // IAC WILL WINDOWSIZE
                client.write("\xFF\xFA\x1F"
                             "\x00\x50\x00\x19"
                             "\xFF\xF0",
                             9); // IAC SB WINDOWSIZE 0 80 0 25 IAC SE
            }
            else if (cmd == 0xFD && opt == 0x18)
            {
                // DO TERMINALTYPE
                client.write("\xFF\xFB\x18", 3); // IAC WILL TERMINALTYPE
            }
            else if (cmd == 0xFA && opt == 0x18)
            {
                // SB TERMINALTYPE
                c = clientWaitForChar(); // bypass '1'
                c = clientWaitForChar(); // bypass IAC
                c = clientWaitForChar(); // bypass SE
                client.write("\xFF\xFA\x18\x00"
                             "wsvt25"
                             "\xFF\xF0",
                             12); // IAC SB TERMINALTYPE 0 "...." IAC SE
            }
            else
            {
                uint8_t pck[3] = {0xFF, 0, opt};
                if (cmd == 0xFD) // DO -> WONT
                    pck[1] = 0xFC;
                else if (cmd == 0xFB) // WILL -> DO
                    pck[1] = 0xFD;
                client.write(pck, 3);
            }
        }
        else
        {
            Terminal.write(c);
        }
    }
    // process data from terminal (keyboard)
    while (Terminal.available())
    {
        client.write(Terminal.read());
    }
    // return to prompt?
    if (!client.connected())
    {
        client.stop();
        state = State::Prompt;
    }
}

void exe_ping()
{
    char host[64];
    auto inputLine = LineEditor.get();
    int pcount = sscanf(inputLine, "ping %s", host);
    if (pcount > 0)
    {
        int sent = 0, recv = 0;
        fabgl::ICMP icmp;
        while (true)
        {

            // CTRL-C ?
            if (Terminal.available() && Terminal.read() == 0x03)
                break;

            int t = icmp.ping(host);
            if (t >= 0)
            {
                Terminal.printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\r\n", icmp.receivedBytes(), icmp.hostIP().toString().c_str(), icmp.receivedSeq(), icmp.receivedTTL(), (double)t / 1000.0);
                delay(1000);
                ++recv;
            }
            else if (t == -2)
            {
                Terminal.printf("Cannot resolve %s: Unknown host\r\n", host);
                break;
            }
            else
            {
                Terminal.printf("Request timeout for icmp_seq %d\r\n", icmp.receivedSeq());
            }
            ++sent;
        }
        if (sent > 0)
        {
            Terminal.printf("--- %s ping statistics ---\r\n", host);
            Terminal.printf("%d packets transmitted, %d packets received, %.1f%% packet loss\r\n", sent, recv, (double)(sent - recv) / sent * 100.0);
        }
    }
    state = State::Prompt;
}

void exe_keyb()
{
    if (PS2Controller.keyboard()->isKeyboardAvailable())
    {
        char layout[3];
        auto inputLine = LineEditor.get();
        if (sscanf(inputLine, "keyb %2s", layout) == 1)
        {
            if (strcasecmp(layout, "US") == 0)
                Terminal.keyboard()->setLayout(&fabgl::USLayout);
            else if (strcasecmp(layout, "UK") == 0)
                Terminal.keyboard()->setLayout(&fabgl::UKLayout);
            else if (strcasecmp(layout, "DE") == 0)
                Terminal.keyboard()->setLayout(&fabgl::GermanLayout);
            else if (strcasecmp(layout, "IT") == 0)
                Terminal.keyboard()->setLayout(&fabgl::ItalianLayout);
            else if (strcasecmp(layout, "ES") == 0)
                Terminal.keyboard()->setLayout(&fabgl::SpanishLayout);
            else if (strcasecmp(layout, "FR") == 0)
                Terminal.keyboard()->setLayout(&fabgl::FrenchLayout);
            else if (strcasecmp(layout, "BE") == 0)
                Terminal.keyboard()->setLayout(&fabgl::BelgianLayout);
            else
            {
                Terminal.printf("Error! Invalid keyboard layout.\r\n");
                state = State::Prompt;
                return;
            }
        }
        Terminal.printf("\r\nKeyboard layout is : \e[93m%s\e[92m\r\n\r\n", Terminal.keyboard()->getLayout()->desc);
    }
    else
    {
        Terminal.printf("No keyboard present\r\n");
    }
    state = State::Prompt;
}

void exe_ssh_init(void)
{
    // Mount the file system.
    error = true;
    boolean fsGood = SPIFFS.begin();

    if (!fsGood)
    {
        Terminal.printf("%% No formatted SPIFFS filesystem found to mount.\r\n");
        Terminal.printf("%% Format SPIFFS and mount now (NB. may cause data loss) [y/n]?\r\n");

        char c = getchar();

        if (c == 'y' || c == 'Y')
        {
            Terminal.printf("%% Formatting...\r\n");
            fsGood = SPIFFS.format();
            if (fsGood)
                SPIFFS.begin();
        }
    }
    if (!fsGood)
    {
        Terminal.printf("%% Aborting now.\r\n");
        while (1)
            vTaskDelay(60000 / portTICK_PERIOD_MS);
    }
    Terminal.printf(
        "%% Mounted SPIFFS used=%d total=%d\r\n", SPIFFS.usedBytes(),
        SPIFFS.totalBytes());
    

    if (WiFi.status() != WL_CONNECTED)
    {
        Terminal.printf("Network not avaliable.\r\n");
        state = State::Prompt;
        return;
    }

    libssh_begin();

    char buffer[256];
    int rbytes, wbytes, total = 0;
    int rc;

    static const int MAX_HOST_SIZE = 32;
    char host[MAX_HOST_SIZE + 1];
    char user[MAX_HOST_SIZE + 1];
    int port;
    auto inputLine = LineEditor.get();
    int pCount = sscanf(inputLine, "ssh %32s %d %s", host, &port, user);
    if (pCount > 0)
    {
        if (pCount == 1)
            port = 22;
        Terminal.printf("Trying %s...\r\n", host);
        
        session = connect_ssh(host, user, port, 0);
        
        if (session != NULL)
        {
            Terminal.printf("Connected to %s\r\n", host);
        }
        else
        {
            ssh_finalize();
            Terminal.write("Unable to connect to remote host\r\n");
            state = State::Prompt;
            return;
        }

        channel = ssh_channel_new(session);
        if (channel == NULL)
        {
            ssh_disconnect(session);
            ssh_free(session);
            ssh_finalize();
            Terminal.write("Unable to create ssh channel\r\n");
            state = State::Prompt;
            return;
        }

        rc = ssh_channel_open_session(channel);
        if (rc < 0)
        {
            goto sshfailed;
        }

        rc = ssh_channel_request_env(channel, "LC_COLORS", "");
        if (rc < 0) 
        {
            Terminal.printf("SSH request enviornment \"LC_COLORS\"=\"\" failed\r\n");
        }

        rc = ssh_channel_request_env(channel, "TERM", "vt100");
        if (rc < 0) 
        {
            Terminal.printf("SSH request enviornment \"TERM\"=\"vt100\" failed\r\n");
        }

        rc = ssh_channel_request_pty(channel);
        if (rc != SSH_OK) goto sshfailed;
        
        rc = ssh_channel_change_pty_size(channel, 80, 24);
        if (rc != SSH_OK) goto sshfailed;
        
        rc = ssh_channel_request_shell(channel);
        if (rc != SSH_OK) goto sshfailed;

        error = false;
        state = State::SSH;
        return;

    sshfailed:
        Terminal.printf("SSH Failed: %s\r\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        ssh_finalize();
    }
    else
    {
        Terminal.write("Mistake\r\n");
    }

    state = State::Prompt;
}

void exe_ssh_stop_session()
{
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_finalize();
    state = State::Prompt;
}

#define SAFE_GET_NEXT_ELEMENT(dst, buffer, offset, nbytes) if(offset < nbytes) dst = buffer[offset]; else break;

volatile uint8_t is_in_iac = 0;
void exe_ssh(void)
{
    char buffer[SSH_MAX_BUFFER_SIZE];
    int nbytes, nwritten;

    // nbytes = ssh_channel_read_nonblocking(channel, buffer, SSH_MAX_BUFFER_SIZE, 0);
    nbytes = ssh_channel_read_timeout(channel, buffer, SSH_MAX_BUFFER_SIZE, 0, 5);
    if (nbytes < 0)
    {
        exe_ssh_stop_session();
        return;
    }
    if (nbytes > 0)
    {
        for (int i = 0; i < nbytes; ++i)
        {
            int c = buffer[i];
            // if (c == 0xFF)
            if (0)
            {
                // IAC (Interpret As Command)
                uint8_t cmd, opt;
                SAFE_GET_NEXT_ELEMENT(cmd, buffer, i + 1, nbytes);
                SAFE_GET_NEXT_ELEMENT(opt, buffer, i + 2, nbytes);
                i += 2;
                if (cmd == 0xFD && opt == 0x1F)
                {
                    const char* data = "\xFF\xFB\x1F" "\xFF\xFA\x1F" "\x00\x50\x00\x19" "\xFF\xF0";
                    nwritten = ssh_channel_write(channel, data, sizeof(data));
                    if (nwritten != sizeof(data))
                    {
                        exe_ssh_stop_session();
                        return;
                    }
                }
                else if (cmd == 0xFD && opt == 0x18)
                {
                    // DO TERMINALTYPE
                    const char* data = "\xFF\xFB\x18";
                    nwritten = ssh_channel_write(channel, data, sizeof(data));
                    if (nwritten != sizeof(data))
                    {
                        exe_ssh_stop_session();
                        return;
                    } // IAC WILL TERMINALTYPE
                }
                else if (cmd == 0xFA && opt == 0x18)
                {
                    // SB TERMINALTYPE
                    SAFE_GET_NEXT_ELEMENT(c, buffer, i + 3, nbytes);
                    i += 3;
                    const char* data = "\xFF\xFA\x18\x00" "wsvt25" "\xFF\xF0";
                    nwritten = ssh_channel_write(channel, data, sizeof(data));
                    if (nwritten != sizeof(data))
                    {
                        exe_ssh_stop_session();
                        return;
                    } // IAC SB TERMINALTYPE 0 "...." IAC SE
                }
                else
                {
                    uint8_t pck[3] = {0xFF, 0, opt};
                    if (cmd == 0xFD) // DO -> WONT
                        pck[1] = 0xFC;
                    else if (cmd == 0xFB) // WILL -> DO
                        pck[1] = 0xFD;
                    nwritten = ssh_channel_write(channel, pck, 3);
                    if (nwritten != 3)
                    {
                        exe_ssh_stop_session();
                        return;
                    }
                }
            }
            else
            {
                Terminal.write(c);
            }
        }
        // Terminal.write(buffer, nbytes);
    }

    // process data from terminal (keyboard)
    nbytes = Terminal.available();
    if (nbytes)
    {
        Terminal.readBytes(buffer, nbytes);
        nwritten = ssh_channel_write(channel, buffer, nbytes);
        if (nwritten != nbytes)
        {
            exe_ssh_stop_session();
            return;
        }
    }

    // return to prompt?
    if (!ssh_channel_is_open(channel) || ssh_channel_is_eof(channel))
    {
        exe_ssh_stop_session();
    }
}

void sshTask(void* args)
{    
    while (true)
    {
        if (state == State::SSHInit)
        {
            exe_ssh_init();
        }
        else if (state == State::SSH)
        {
            exe_ssh();
        }
        else
        {
            break;
        }
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

int terminal_std_write(_reent *fp, void *buf, const char *src, int size)
{
    return Terminal.write(src, (size_t)size);
}

int terminal_std_read(_reent *fp, void *buf, char *dst, int size)
{
    return Terminal.readBytes(dst, size);
}

void redirect_stdio(void)
{
    Terminal.setTimeout(1000 * 1000);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    stdout->_write = &terminal_std_write;
    stderr->_write = &terminal_std_write;
    stdin->_read = &terminal_std_read;
}

void redirect_terminal_test(void)
{
    Terminal.printf("Redirect loopback test.\r\n");
    while (true)
    {
        fputc(fgetc(stdin), stdout);
    }
}

// auto full_bright = DisplayController.createRawPixel(RGB222(0, 3, 0));
// auto half_bright = DisplayController.createRawPixel(RGB222(3, 0, 0));
// auto bgcolor = DisplayController.createRawPixel(RGB222(0, 0, 0));

void setup()
{
    Serial.begin(115200); // DEBUG ONLY

    devState = STATE_NEW;
#if ESP_IDF_VERSION_MAJOR >= 4
    //WiFi.setHostname("libssh_esp32");
    esp_netif_init();
#else
    tcpip_adapter_init();
#endif
    // esp_event_loop_init(event_cb, NULL);

    // Stack size needs to be larger, so continue in a new task.
    // xTaskCreatePinnedToCore(controlTask, "ctl", configSTACK, NULL,
    //                         (tskIDLE_PRIORITY + 3), NULL, portNUM_PROCESSORS - 1);

    PS2Controller.begin();

    DisplayController.begin((gpio_num_t)12, (gpio_num_t)2, (gpio_num_t)0, (gpio_num_t)14, (gpio_num_t)13);
    DisplayController.setResolution();

    Terminal.begin(&DisplayController);
    Terminal.connectLocally();     // to use Terminal.read(), available(), etc..
    Terminal.setLogStream(Serial); // DEBUG ONLY

    Terminal.setBackgroundColor(Color::Black);
    Terminal.setForegroundColor(Color::BrightGreen);
    Terminal.clear();

    Terminal.enableCursor(true);

    currentScript = AUTOEXEC;
// CONFIG_MAIN_TASK_STACK_SIZE
    redirect_stdio();
    // redirect_terminal_test();
}

void loop()
{
    switch (state)
    {

    case State::Prompt:
        exe_prompt();
        break;

    case State::PromptInput:
        exe_promptInput();
        break;

    case State::SSHStart:
        state = State::SSHInit;
        xTaskCreatePinnedToCore(sshTask, "sshTask", configSTACK, NULL,
                            (tskIDLE_PRIORITY + 3), NULL, 1);
        break;

    case State::SSHInit:
    case State::SSH:
        vTaskDelay(50 / portTICK_PERIOD_MS);
        break;

    case State::Help:
        exe_help();
        break;

    case State::Info:
        exe_info();
        break;

    case State::Wifi:
        exe_wifi();
        break;

    case State::TelnetInit:
        exe_telnetInit();
        break;

    case State::Telnet:
        exe_telnet();
        break;

    case State::Scan:
        exe_scan();
        break;

    case State::Ping:
        exe_ping();
        break;

    case State::Reset:
        ESP.restart();
        break;

    case State::Keyb:
        exe_keyb();
        break;

    case State::UnknownCommand:
        Terminal.write("\r\nMistake\r\n");
        state = State::Prompt;
        break;

    default:
        Terminal.write("\r\nNot Implemeted\r\n");
        state = State::Prompt;
        break;
    }
}
