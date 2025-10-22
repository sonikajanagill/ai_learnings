import com.theokanning.openai.OpenAiService;
import com.theokanning.openai.completion.chat.*;
import com.theokanning.openai.service.FunctionExecutor;
import java.util.*;

public class FunctionCallingExample {
    public static void main(String[] args) {
        OpenAiService service = new OpenAiService("your-api-key");
        
        // Define function
        ChatFunction weatherFunction = ChatFunction.builder()
            .name("get_weather")
            .description("Get weather for a location")
            .executor(WeatherFunction.class, w -> w.getWeather())
            .build();
        
        // Create function executor
        FunctionExecutor functionExecutor = new FunctionExecutor(
            Collections.singletonList(weatherFunction)
        );
        
        // Create chat message
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(
            "user", 
            "What's the weather in London?"
        ));
        
        // Make request with functions
        ChatCompletionRequest request = ChatCompletionRequest.builder()
            .model("gpt-4o")
            .messages(messages)
            .functions(functionExecutor.getFunctions())
            .build();
        
        ChatCompletionResult result = service.createChatCompletion(request);
        ChatMessage response = result.getChoices().get(0).getMessage();
        
        // Check for function call
        if (response.getFunctionCall() != null) {
            String functionName = response.getFunctionCall().getName();
            String arguments = response.getFunctionCall().getArguments();
            System.out.println("Function: " + functionName);
            System.out.println("Arguments: " + arguments);
        }
    }
}