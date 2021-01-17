## Notes
These were made for / tested on the `VMG8825-T50` device for the Dutch market, but might well work on other variants or even other models.

These are hacky scripts, so no guarantees. I'm also not keeping this up to date so the underlying vulnerabilities might be patched by the time you read this.

## Authenticated web-interface command injections 
The majority of the code in the authenticated PoCs below is needed for setting up a proper session with the device's web-interface. For some reason this uses a weird AES-based protocol. Yay for security through obscurity!

Make sure to `pip install cryptodome` for these.

- `cmd_injection_ping.py`
	- PoC for authenticated command injection in diagnostics tools (`/cgi-bin/DAL?oid=PINGTEST`)
	- results in the root password and an SSH server running on port 2222. i.e. a root shell.
	- still works as of January 2021, firmware `V5.50(ABPY.1)b15_20201207` 
- `cmd_injection_wol.py`
	- PoC for authenticated command injection in Wake-on-LAN command (`/cgi-bin/Home_Networking?action=WOLCommand`).
	- unpolished, edit the file first! By default it opens a connect-back shell on port 1337, so make sure to start a netcat listener.
	- found in `V5.50(ABPY.1)b11`, patched somewhere around firmware `V5.50(ABPY.1)b14`, in summer/fall 2020.


## Unauthenticated memory corruption
There are at least 2 buffer overflows in some of the authenticated DAL commands of the web-interface (and probably more), but I haven't tried exploiting them yet. Command injections are easier anyway as long as they're not patched.

I did however look into unauthenticated buffer overflows and DoS. One of which was in the general HTTP GET handler, as detailed in [my blogpost](https://th0mas.nl/2020/11/17/exploiting-a-stack-based-buffer-overflow-in-practice/) and in [Zyxel's advisory](https://www.zyxel.com/support/Zyxel-security-advisory-for-remote-code-execution-and-denial-of-service-vulnerabilities-of-CPE.shtml). This was fixed in `V5.50(ABPY.1)b15_20201207` for the `T50` variant, and other versions for a few dozen VMG devices.

These are the relevant scripts. Bypassing ASLR is left as an exercise for the reader.

- `urloverflow2.py`
	- The buffer overflow as described in the post linked above, with an attempted ASLR-bruteforce wrapper, which isn't super succesful.
- `postoverflow2.py`
	- A specific POST requests that causes a segfault. Seemingly not exploitable but a fun DoS if spammed.


## Other

A combinations of vulnerabilities / design flaws used to allow for [authenticated root access](https://th0mas.nl/2020/03/26/getting-root-on-a-zyxel-vmg8825-t50-router/) in firmware `V5.50(ABPY.0)b12_20190730`:
- The DLNA server is running as root and follows symlinks on ext2 partitions on connected USB drives
- The device's backed-up config file could be edited to enable certain management features and enable SSH access

The latter has since been fixed (as of `V5.50(ABPY.1)b11`, I think) by encrypting the config file. This trick can therefore no longer be used to get a shell.