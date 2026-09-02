# NIST SP 800-171 Rev 2: 110 controls in 14 families. CMMC 2.0 Level 2 is
# exactly these; Level 1 is the 17 that come from FAR 52.204-21.
FAMILY = {1:"AC",2:"AT",3:"AU",4:"CM",5:"IA",6:"IR",7:"MA",8:"MP",
          9:"PS",10:"PE",11:"RA",12:"CA",13:"SC",14:"SI"}
COUNT  = {1:22,2:3,3:9,4:9,5:11,6:3,7:6,8:9,9:2,10:6,11:3,12:4,13:16,14:7}
L1 = {"3.1.1","3.1.2","3.1.20","3.1.22","3.5.1","3.5.2","3.8.3",
      "3.10.1","3.10.3","3.10.4","3.10.5","3.13.1","3.13.5",
      "3.14.1","3.14.2","3.14.4","3.14.5"}

def canonical():
    """control number -> the one correct CMMC practice id."""
    out = {}
    for fam, n in COUNT.items():
        for i in range(1, n + 1):
            num = "3.%d.%d" % (fam, i)
            lvl = "L1" if num in L1 else "L2"
            out[num] = "%s.%s-%s" % (FAMILY[fam], lvl, num)
    return out
