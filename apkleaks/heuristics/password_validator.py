
PASSWORD_LENGTH = [4, 64]

class PasswordValidator():
    def __init__(self):
        pass

    def validatePassword(self, password):
        results = list()

        if not self.__checkLength(password):
            results.append("Doesn't match the standard password lenght!")

        if not self.__check_upper_lower(password):
            results.append("Doesn't containt upper and lower characters!")

        if not self.check_numbers(password):
            results.append("Doesn't contain any number!")

        return results

    def __checkLength(self, password):
        if len(password) >= PASSWORD_LENGTH[0] and len(password) <= PASSWORD_LENGTH[1]:
            return True
        else:
            return False

    def __check_upper_lower(self, password):
        res_upper = any(ele.isupper() for ele in password) 
        res_lower = any(ele.islower() for ele in password) 

        if res_upper and res_lower:
            return True
        else:
            return False
    
    def check_numbers(self, password):
        return any(char.isdigit() for char in password)
