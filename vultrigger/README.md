Joern Slice
========

Installation
------------
 
Install joern-slice by running:
 
    pip install joern-slice


Basic using
-------
Look how easy it is to use:
 
        from joern_slice.cv_extract import extract_info

        diff_path = './data' #diff文件路径
        info_path = './diff_info' #关键变量保存路径
        extract_info(diff_path, info_path)
 
Data file directory structure
--------

        data/
            ├── software1/
            │   ├── CVE-2017-xxxx/
            │   │   └──  patch.diff
            │   ├── CVE-2017-xxxx/
            │   │   └──  patch.diff
            │   └── CVE-2017-xxxx/
            │       └──  patch.diff
            └── software2/
                ├── CVE-2019-xxxx/
                │   └──  patch.diff
                ├── CVE-2019-xxxx/
                │   └── patch.diff
                └── CVE-2019-xxxx/
                    └──  patch.diff
    



 

 
