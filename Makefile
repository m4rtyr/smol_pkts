SRC=pkt.c
TARGET=smol_pkts

all:
	cc -g -Wall $(SRC) $(TARGET).c -o $(TARGET)
clean:
	rm -rf $(TARGET) *.dSYM
