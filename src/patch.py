import pefile

pe = pefile.PE("spoonfed-v1.exe")
pe.sections[0].Characteristics |= 0x80000000

buff = pe.write()
pe.close()
with open("spoonfed-v1.exe", "wb") as f:
    f.write(buff) 
