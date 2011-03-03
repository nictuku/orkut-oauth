run: clean orkut-oauth 
	./orkut-oauth
 
include $(GOROOT)/src/Make.inc

TARG=orkut-oauth
GOFILES=\
    main.go\

include $(GOROOT)/src/Make.cmd
