A = sys_number                                                                                                                       
A == faccessat ? lol : done
lol:
return ERRNO(5)
done:
return ALLOW
kill:
return KILL
