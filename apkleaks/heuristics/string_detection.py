import base64

class StringDetection():
    def __init__(self):
        pass

    def detect_string(self, line, sequence_length=0, no_length=False):
        for i in range(len(line)):
                line_quote_sequence = line[i:i+1]
                if line_quote_sequence == "\"":
                    if no_length == True or i+sequence_length+1 < len(line) and line[i+sequence_length+1:i+sequence_length+2] == "\"":
                        
                        begin_line_sequence = i+1
                        end_line_sequence = begin_line_sequence

                        if no_length == True:
                            for x in range(i+1, (i+1)+len(line[i+1:])):
                                if line[x:x+1] == "\"":
                                    end_line_sequence = x

                                    break
                        else:
                            end_line_sequence = i+sequence_length+1
                    

                        line_sequence = line[begin_line_sequence:end_line_sequence]
                        return line_sequence
                        
        return False	