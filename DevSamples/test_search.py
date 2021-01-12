import ida_loader
import lief

def search_executable():
    """ try to locate binary corresponding to the IDB
        to parse dynamic information (PT_DYNAMIC segment) 
    """

    f_path_l=ida_loader.get_path(ida_loader.PATH_TYPE_CMD).split('.')[:-1]
    ntry=1
    f_path=""
    print(f_path_l)
    print(len(f_path_l))
    while ntry<len(f_path_l):
        candidate='.'.join(f_path_l[0:ntry])
        print(candidate)
        if os.path.exists(candidate):
            if str(lief.ELF.parse(candidate)) != None:
                f_path=candidate
                break
        else:
            ntry+=1


    if f_path == "":
        logger.console(LogType.WARN,"cannot find suitable executable, please enter manually")


    return f_path




if __name__ == '__main__':
    print(search_executable())
