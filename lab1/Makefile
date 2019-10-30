CXX		  	:= g++
CXX_FLAGS 	:= -Wall -Wextra -std=c++17 -ggdb -c

LD		  	:= ld

BIN_DIR		:= bin
SRC_DIR		:= src
OBJ_DIR 	:= obj

SRC			:= $(wildcard $(SRC_DIR)/*.cpp)
OBJ			:= $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o, $(SRC))
		

INCLUDE		:= -Iinclude \
			   -I/home/boris/cpp_json/include

LIB			:= -Llib

LIBRARIES	:=
			   
EXECUTABLE	:= main

LIBTEXT_PATH:= ..


all: $(OBJ_DIR) $(BIN_DIR) $(OBJ) $(BIN_DIR)/$(EXECUTABLE)

text_lib: $(OBJ_DIR)
	@echo "Create 'Text' static library..."
	$(CXX) $(CXX_FLAGS) $(INCLUDE)  $(SRC_DIR)/file.cpp  -o $(OBJ_DIR)/file.o
	$(CXX) $(CXX_FLAGS) $(INCLUDE)  $(SRC_DIR)/alph.cpp  -o $(OBJ_DIR)/alph.o
	$(CXX) $(CXX_FLAGS) $(INCLUDE)  $(SRC_DIR)/fdict.cpp -o $(OBJ_DIR)/fdict.o
	$(CXX) $(CXX_FLAGS) $(INCLUDE)  $(SRC_DIR)/text.cpp  -o $(OBJ_DIR)/text.o
	ar rcs $(LIBTEXT_PATH)/libtext.a $(OBJ_DIR)/file.o $(OBJ_DIR)/alph.o $(OBJ_DIR)/fdict.o $(OBJ_DIR)/text.o

$(OBJ_DIR):
	@echo "Creating obj dir"
	@mkdir $(OBJ_DIR)

$(BIN_DIR):
	@echo "Creating exec dir"
	@mkdir $(BIN_DIR)

$(OBJ): $(OBJ_DIR)/%.o:  $(SRC_DIR)/%.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE) $^ -o $@

$(BIN_DIR)/$(EXECUTABLE): $(OBJ)
	$(CXX) $(LIB) $^ -o $@ $(LIBRARIES)

run: clean all
	clear
	./$(BIN_DIR)/$(EXECUTABLE)

clean:
	-rm $(BIN_DIR)/*

cleanall: clean
	rm -rf $(OBJ_DIR)
	rm -f  $(LIBTEXT_PATH)/libtext.a
