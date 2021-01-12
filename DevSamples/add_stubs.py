import sys , os, shutil


if __name__ == '__main__':
  
  print('[!] please specify an additionnal file')
  path = input()


  pdir,fname = os.path.split(path)
#   sys.path.insert(0,pdir)
#   os.mknod(os.path.join(pdir,'user_stubs.py'))
  shutil.copy(path,os.path.join(os.getcwd(),'user_stubs.py'))
  
  import user_stubs 

  
