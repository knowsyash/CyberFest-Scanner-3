#By import queue

from queue import  Queue
AA = Queue (maxsize=6)
print("Initial size before insertion", AA.qsize())
AA.put("J")
AA.put("K@")
AA.put("L!!")
#AA.put("H###")
#AA.put("F$$$$")
#AA.put("S%%%%")
print("After insertion :", AA.qsize())
print("AA is full or not ? :",AA.full())
print("Size of the queue:", AA.qsize())

print("Removing element")
print(AA.get())
#print(AA.get())
print(AA.get())
print("Empty or not ? :",AA.empty())
print(AA.get())
print("Empty or not ? :",AA.empty())
print("Size of the queue", AA.qsize())
