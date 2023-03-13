package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PrototypePollutionBodyScanTest {

    @Test
    @DisplayName("Testing the JSON serializer")
    void generateJsonStringSerializationChecksTest() {
        JsonParser parser = new JsonParser();
        String[] jsonStrings = new String[]{
                "{}", "{\"x\":[]}", "{\"x\":{}}", "{\"x\":{},\"y\":{}}", "{\"x\":[1,2,3],\"y\":{}}","[]", "[{}]"
        };
        for(int i=0;i<jsonStrings.length;i++) {
            String jsonString = jsonStrings[i];
            JsonElement json = parser.parse(jsonString);
            System.out.println("JSON:"+json);
            assertEquals(jsonString, PrototypePollutionBodyScan.generateJsonString(json, null, null, null, null));
        }
    }

    @Test
    @DisplayName("Testing JSON serializer assignments")
    void generateJsonStringAssignmentTest() {
        JsonParser parser = new JsonParser();
        String[][] jsonStrings = {
                {"{\"a\":123}", "{\"b\":{}}", "a", "b", "{}"},
                {"{\"test1\":123}", "{\"test2\":[1,2,3]}", "test1", "test2", "[1,2,3]"}
        };
        for(int i=0;i<jsonStrings.length;i++) {
            String jsonString = jsonStrings[i][0];
            String expectedJsonString = jsonStrings[i][1];
            JsonElement json = parser.parse(jsonString);
            JsonObject target = json.getAsJsonObject();
            String existingProperty = jsonStrings[i][2];
            String newPropertyName = jsonStrings[i][3];
            JsonElement value = parser.parse(jsonStrings[i][4]);
            assertEquals(expectedJsonString, PrototypePollutionBodyScan.generateJsonString(json,  target, existingProperty, newPropertyName, value));
        }
    }
}