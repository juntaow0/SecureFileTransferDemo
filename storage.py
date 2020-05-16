import os, sys, time, shutil

class serverFileSystem:
    rootDir = ''
    currentDir = {}
    
    def __init__(self, path, users):
        self.rootDir = path
        if not os.path.exists(self.rootDir):
            os.mkdir(self.rootDir)
        
        for user in users:
            userDir = self.rootDir+user
            if not os.path.exists(userDir):
                os.mkdir(userDir)
                
        for user in users:
            self.currentDir[user] = '/'
    
    def getCurrentDir(self, user):
        return 'HOME' + self.currentDir[user]
        
    def makeDir(self, user, dirName):
        if dirName == 'HOME':
            return False
        if ' ' in dirName:
            return False
        path = self.rootDir+'/'+user+self.currentDir[user]+dirName
        if (os.path.exists(path)):
            return False
        os.mkdir(path)
        return True
            
    def removeFile(self, user, filename):
        path = self.rootDir+'/'+user+self.currentDir[user]
        if (filename in os.listdir(path)):
            os.remove(path+filename)
            return True
        return False
    
    def removeDir(self, user, folder):
        path = self.rootDir+'/'+user+self.currentDir[user]
        if (folder in os.listdir(path)):
            try: 
                os.rmdir(path+folder) 
                return True
            except OSError as error: 
                print(error) 
        return False
        
    def listDir(self, user):
        path = self.rootDir+'/'+user+self.currentDir[user]
        items = os.listdir(path)
        itemString = "Nothing to be seen here."
        if len(items)>0:
            template = '{0:<40} {1:<8}\n'
            itemString = template.format('Name','Type')+'\n'
            for i in items:
                cat = 'File'
                if os.path.isdir(path+i):
                    cat = 'Folder'
                itemString+=template.format(i,cat)
        return itemString
        
    def changeDir(self, user, dirName):
        if dirName == '':
            return True
        if dirName[-1]!= '/':
            dirName+='/'
        if (dirName[0:5]=='HOME/'):
            path = self.rootDir+'/'+user+dirName[4:]
            if (os.path.exists(path)):
                self.currentDir[user] = dirName[4:]
                return True
        newDir = self.currentDir[user]+dirName
        path = self.rootDir+'/'+user+newDir
        if (os.path.exists(path)):
            self.currentDir[user] = newDir
            return True
        return False
        
    def upload(self, user, filename):
        if not os.path.exists(filename):
            return False
        path = self.rootDir+'/'+user+self.currentDir[user]
        shutil.copy2(filename, path)
        return True
        
    def download(self, user, filename, dst):
        if not os.path.exists(dst):
            return False
        path = self.rootDir+'/'+user+self.currentDir[user]
        if filename not in os.listdir(path):
            return False
        if os.path.isdir(path+filename):
            return False
        shutil.copy2(path+filename, dst)
        return True
        
    def getHelp(self):
        doc = "Here are all the commands:\n"+ \
        "HLP: display help.\n"+ \
        "LGO: logout.\n" + \
        "MKD <folder name>: create a folder in current directory. NO WHITE SPACE.\n" + \
        "RMD <folder name>: remove an EMPTY folder in current directory.\n" + \
        "GWD: display current directory.\n" + \
        "CWD <path>: move to given directory.\n" + \
        "LST: display files and folders in current directory.\n" + \
        "UPL <file path>: upload a file to current directory. NO WHITE SPACE.\n" + \
        "DNL <filename> <destination>: download a file in current directory to destination. NO WHITE SPACE.\n" + \
        "RMF <filename>:  delete a file in current directory.\n"
        return doc
        