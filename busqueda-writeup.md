# Hack The Box Busqueda Writeup

![busqueda title card](images/busqueda/busqueda.png)

Busqueda is an easy difficulty machine available from Hack The Box. While playing the machine, we encounter concepts such as ...

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

`Flask` is a reasonably common occurence, but `Searchor` is not so common. A quick google of `Searchor` reveals that it is a python library that is used to perform web scraping, giving the web app it's searching powers. If we Google for the particular *version* that the web application is using (`2.4.0`), we find some interesting results. 

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

The [Searchor Github respository](https://github.com/ArjunSharda/Searchor) shows us where the bug is. When bugs are concerned, the `Issues` page is the first place to start. Since we already know what we're looking for, we can just search for `eval`. 

![searchor eval issue](images/busqueda/busqueda-pr.PNG)

There we have it, one of the project collaborators created an issue to fix the dangerous use of `eval`. If we open up the issue and go to the `Commits` tab, we can view the diff to see what was changed. 

![searchor diff](images/busqueda/busqueda-diff.PNG)

Here we can see the structure of the code *before* the fix was merged into the project. The `search` function uses `eval` to craft the URL as a format string. Notice that the `query` parameter is being inserted into `eval` without any kind of sanitization. This is likely going to be our entry point. 

## Searcher

Now that we know the library that the app is using has an unsafe `eval` flaw in it, let's see how the *Searcher website* works. If we open up Burp Suite and route our web traffic through its proxy, we can observe and mess with the requests that are sent. 

![search request](images/busqueda/busqueda-search.PNG)

It looks to be a simple POST request, with the chosen search engine and query being sent as the payload. To play around with the request, hit `CTRL+R` to send it to the Burp Repeater. 

# Foothold

There are plenty of pre-written scripts that will exploit the `Searchor` arbitrary code execution bug for you, but being able to exploit something manually is still an important skill to have. This is especially true for new vulnerabilities that appear which may not have any proof-of-concept code available. 



## User Flag



# Privilege Escalation



## Root Flag



# References

- 
- 

# Tools Used

- [Burp Suite](https://portswigger.net/burp/communitydownload)
- [Snyk Vulnerability Database - searchor@2.4.0](https://security.snyk.io/package/pip/searchor/2.4.0)
- 