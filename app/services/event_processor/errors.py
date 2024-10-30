class InvalidEvent(Exception):
    """
    Exception raised when an Event is invalid
    
    Attributes:
    message: Explanation of the error
    """
    def __init__(self, message="Invalid event"):
        self.message = message
        super().__init__(self.message)
    
class KafkaConnectionFailure(Exception):
    """
    Exception raised when the Kafka connection fails
    
    Attributes:
    message: Explanation of the error
    """
    def __init__(self, message="Kafka connection failure"):
        self.message = message
        super().__init__(self.message)
