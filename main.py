import argparse
import sys
def analyzer(fl):
    file=open("fl","r")
    counter=1
    for line in file:#all main javascript functions that have vulnerabilities
        if "document.write(" in line:
            print(fl+"[" + str(counter)+"] HTML MANIPULATION:"+ line)
        if "document.writeln(" in line:
            print(fl+"[" + str(counter)+"] HTML MANIPULATION:"+ line)
        if "anyElement.innerHTML(" in line:
            print(fl+"[" + str(counter)+"] HTML MANIPULATION:"+ line)
        if "anyElement.outerHTML(" in line:
            print(fl+"[" + str(counter)+"] HTML MANIPULATION:"+ line)
        if "document.location.href.substring(" in line:
            print(fl+"[" + str(counter)+"] DOM BASED XSS:"+ line)
        if " eval( document.forms[0]." in line:
            print(fl+"[" + str(counter)+"] DOM BASED XSS:"+ line)
        if " location.ref" in line:
            print(fl + "[" + str(counter) + "] LOCATION BASED:" + line)
        if "document.cookies" in line:
            print(fl + "[" + str(counter) + "] CLIENT BASED STORAGE" + line)
        if "navigation.referrer" in line:
            print(fl + "[" + str(counter) + "] NAVIGATION BASED" + line)
        if " setInterval" in line:
            print(fl + "[" + str(counter) + "] EXECUTION BASED:" + line)
        if " setTimeout" in line:
            print(fl + "[" + str(counter) + "] EXECUTION BASED:" + line)
        if " location.assign(" in line:
            print(fl + "[" + str(counter) + "] URL BASED:" + line)
        counter+=1
if "__name__"=="__main__":
    srcfile=''
    if len(sys.argv)<2:
        print("JAVA SCRIPT SOURCE CODE ANALYZER\n")
        print(sys.argv[0]+"<sourcefile>\n")
        quit()
    else:
        srcfile=sys.argv[1]
    analyzer(srcfile)







