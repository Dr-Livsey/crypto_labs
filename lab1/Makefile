CXX		  := g++
CXX_FLAGS := -Wall -Wextra -std=c++17 -ggdb -fPIC

BIN		:= bin
SRC		:= src

INCLUDE	:= -Iinclude

LIB		:= -Llib

LIBRARIES	:=
			   
EXECUTABLE	:= main


all: $(BIN)/$(EXECUTABLE)

run: clean all
	clear
	./$(BIN)/$(EXECUTABLE)

$(BIN)/$(EXECUTABLE): $(SRC)/*.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE) $(LIB) $^ -o $@ $(LIBRARIES)

clean:
	-rm $(BIN)/*
