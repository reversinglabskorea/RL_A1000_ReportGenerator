# ReversingLabs A1000 Report Generator

## Summary
A1000 api를 Report 형식으로 시각화하는 프로그램

## How to use
1. install python 3.7
2. jinja2 설치
```
pip install jinja2
```
3. 실행
```
py reportGenerator.py --auth authfile -u/--upload samplefilelist
```
**authfile example**
  - space로 구분
```
addr ****
username ****
password ****
```

  **samplefilelist example**
  - file 경로 작성, enterkey로 구분, hash값(SHA1) 입력시 맨 앞에 ~ 붙임(업로드 하지않고 hash값을 통한 정보 검색만 진행)
```
C:\test\testfile.zip
D:\reversinglabs\test2.text
~ce7e591a2a772a2f320b***d3120e168eb07ddb4
```

4. 결과 파일 생성

 - summarypage.html
    - 1_filename.html
    - 1_filename_TiCloud.html
    - 2_filename.html
    - 2_filename_TiCloud.html
    - ...
