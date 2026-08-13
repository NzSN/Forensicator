# Timeline
I hope that Forensicator to be not just a program to rebuild program model from dump only but 
also a program that to accelerate reasoning for the cause chain of the directly exception. 

Above is the future of Forensicator. Currently, I want to solid the foundation of infromations or 
knowledges of program in two dimension (Threads x Timeline). A single point of timeline is correspond
to position of a ttd trace (*.run). The state of Timeline is empty initially and filled lazily by 
query for proxy.

Point of timeline should be shared the abstraction by dump (Model.tla) hence analyzer could work on it.
