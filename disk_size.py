disk_size = 2e+12 # 2TB hard drive
hash_size = 20 # standard SHA-1 output size
alphabet = 62 # only alphanumeric for now
i = 1
while hash_size*(alphabet**i) < disk_size:
    print("{}% of disk space needed for hashes of all {} char passwords"
          .format((hash_size*(alphabet**i))/disk_size * 100, i))
    i+=1
