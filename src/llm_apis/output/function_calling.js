import OpenAI from "openai";

const openai = new OpenAI();

const tools = [{
    type: "function",
    function: {
        name: "get_weather",
        description: "Get weather for a location",
        parameters: {
            type: "object",
            properties: {
                location: { type: "string" },
                unit: { 
                    type: "string", 
                    enum: ["celsius", "fahrenheit"] 
                }
            },
            required: ["location"]
        }
    }
}];

const response = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ 
        role: "user", 
        content: "What's the weather in London?" 
    }],
    tools: tools
});

// Check if function was called
if (response.choices[0].message.tool_calls) {
    const toolCall = response.choices[0].message.tool_calls[0];
    console.log(`Function: ${toolCall.function.name}`);
    console.log(`Arguments: ${toolCall.function.arguments}`);
}