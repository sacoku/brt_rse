## BRT-RSE Makefile

INC		:= -I./ -I./include -I../json-c -I../zlog/src

CFLAGS	:= $(INC) -Wall -O2 -g -mbig-endian

LDFLAGS	:= -L../json-c/.libs -L../zlog/src
LDFLAGS += -ljson-c -lm -lpthread -lzlog

OBJDIR	:= objs
SRCS	:= $(shell find . -regex '.*\.\(c\|cpp\)')
OBJS	:= $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

TARGET	:= brsed

.SUFFIXES : .c .o

all : $(TARGET)

prepare :
	@if [ ! -d $(OBJDIR) ]; then	\
		mkdir -p $(OBJDIR);			\
	fi

$(TARGET) : prepare $(OBJS)
	@$(EC) -e "\e[1;32mLinking ... [$@]\e[0m"
	@$(CC) -o $@ $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: %.c
	@$(EC) -e "\e[0;31mCompiling [C] $<\e[0m"
	@$(CC) -o $@ $< -c $(CFLAGS)

clean:
	@$(EC) "Cleaning...."
	@$(RM) $(OBJDIR) $(TARGET)
