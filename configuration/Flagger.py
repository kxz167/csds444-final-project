import re

class Flagger:
    def __init__(
        self, 
        show_step, 
        show_step_description,
        pause_on_step
    ):
        self.show_step = show_step
        self.show_step_description = show_step_description
        self.pause_on_step = pause_on_step
        self.step_count = 0

    @classmethod
    def init(self):
        flag_values = [False, False, False]

        if("y" in input("Show steps? [y/n]: ")):
            flag_values[0] = True
            if("y" in input("Show step descriptions? [y/n]: ")):
                flag_values[1] = True

            if("y" in input("Pause on each step? [y/n]: ")):
                    flag_values[2] = True
        return Flagger(flag_values[0], flag_values[1], flag_values[2])

    '''
    Performs any blocking or printing of information
    @param step: The output of the encryption step
    @param message: The description of the encryption step.
    '''
    def handle (self, step, message):
        compiled_output = (None, None)
        if(self.show_step):
            if(self.show_step_description):
                compiled_output = (step, message)
            else:
                compiled_output = (step, None)
            
            self.output(compiled_output)

            if(self.pause_on_step):
                self.pause()

    def pause (self):
        input("Press Enter to continue.")


    '''
    Dependingo on UI, print or return message
    '''
    def output(self, to_screen):
        # Command line:
        self.print_output(to_screen)
        
    
    def print_output (self, output):
        if(output[0] != None):
            print("----------------------------")
            print(output[0])

            if(output[1] != None):
                print(output[1])
                print("----------------------------")
            else:
                print("----------------------------")