## Neptune
This is the network intrusion detection system directory, containing all files
required for its operation.
It includes training and testing stats files, a classifier utilities script which
provides functionality to evaluate the different classifiers, and also provides the
NIDS itself.

<p align="center">
  <img src="../imgs/NeptuneProcess.png?raw=true" alt="Neptune Process Flow" width="600" />
</p>

## TestManager
This is the Hydra TestManager package which contains the adversarial testing tool
classes.  This involves the handling of test submission from the UI.

The package performs three core functions:

    1.) Receives user submitted test
    
    2.) Launches SDN and Neptune (NIDS)
    
    3.) Executes adversarial test
    
    4.) Returns results to the web application
    
    
Furthermore, other functionality and scripts are included which enabled the research
and also enabled live detection accuracy testing of Neptune (before adversarial
techniques were introduced).


## nids_config
A shared configuration folder.

Enables communication between Neptune and the TestManager.  TestManager writes
settings such as the classifier requested in the test.  Intrusion results and the
training status are also written here.

