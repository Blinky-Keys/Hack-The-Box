# Hack The Box Inject Writeup

![inject title card](images/inject//inject.png)

Inject is an easy difficulty machine from Hack The Box. 

While playing this machine, we encounter concepts including arbitrary file reading, Spring Cloud, and Ansible. 

# Enumeration

Let's begin with some reconnaissance. 

## Nmap

We begin by scanning the box with `nmap`. 

```bash
nmap -sC -sV TARGET-IP > scan.txt
```

After we let `nmap` run for a bit, we see the following results:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-12 23:00 NZDT
Nmap scan report for 10.10.11.204
Host is up (0.048s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.44 seconds
```

We can see that there are two ports open on the box:

- SSH on port 22
- Web application on port 8080

Let's go and take a look at the web app. 

## Web Application

It looks to be a website advertising a file hosting service.

![zodd cloud homepage](images/inject//inject-website.PNG)

Most of the links on the page don't actually go anywhere, though one does catch my eye. The `Upload` link looks like it could be promising. 

As expected, we're greeted with a file upload form. 

![inject file upload](images/inject/inject-upload.PNG)

The first thing I would think to try is to upload some kind of web shell in an attempt to gain remote code execution on the box. The only issue with that approach is that the server restricts the type of file that can be uploaded to images. With that being the case, let's upload an image to see what the box does with it. 

### File Upload

After uploading the image, we're given a link that takes us to a page that displays the image back to us. Seems pretty straight forward. However, take a closer look at the URL of the page...

```
http://TARGET-IP:8080/show_image?img=test.jpeg
```

Notice that the name of the file is being included as a parameter to tell the `show_image` page which image file it should display. When I see URLs like that, the first thing I do is try to mess with it. 

### Directory Traversal

Let's see if we can change the parameter so that the page displays a different file. 

```
http://TARGET-IP:8080/show_image?img=../../../../../../../../etc/passwd
```

This time we get something different back. 

```
The image "http://TARGET-IP:8080/show_image?img=../../../../../../../../etc/passwd" cannot be displayed because it contains errors. 
```

I've seen this error appear when a browser is attempting to display a non-image file as an image. To get around this, let's put our request through the Burp Repeater. 

![inject burp repeater](images/inject/inject-burp.PNG)

Look at that, we can read `/etc/passwd`! Now that we know we can read any file we want, we can abuse the `show_image` page to take a look around the file system. Let's see what is in the folder one level up from the `show_image` page. We can modify the request URL to the following to achieve this:

```
http://TARGET-IP:8080/show_image?img=../
```

We see the following directories listed:

```
java
resources
uploads
```

Looks like we're interacting with a web app written in Java. `uploads` is most likely going to be where our image files are going. Let's keep going up the file tree. After heading up a few more levels, we can see some other interesting files. 

```
.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```

### POM.xml

The important file to note here is `pom.xml`. This file is found inside projects that are built with Apache Maven. Maven is a build automation tool that is mostly used with Java projects, but can also be used for applications written in other languages too. In the context of Maven, `pom` stands for Project Object Model. The `pom.xml` file contains information about the project, its dependencies, and configuration information that Maven uses to build the project. Let's take a look at the POM. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```

Here we can see the dependencies for the project. Note that the version numbers are also included. Let's put some of those package names and version numbers into Google and see if anything interesting comes back. 