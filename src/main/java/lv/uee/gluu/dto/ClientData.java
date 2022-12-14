package lv.uee.gluu.dto;

import lv.uee.gluu.exception.BadInputException;
import lv.uee.gluu.utils.Base64Util;

import java.io.IOException;
import java.io.Serializable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
public class ClientData implements Serializable {

    private static final long serialVersionUID = -1483378146391551962L;

    private static final String TYPE_PARAM = "typ";
    private static final String CHALLENGE_PARAM = "challenge";
    private static final String ORIGIN_PARAM = "origin";

    private final String typ;
    private final String challenge;
    private final String origin;
    private final String rawClientData;
    private final JsonNode data;

    public ClientData(String clientData) throws BadInputException {
        this.rawClientData = new String(Base64Util.base64urldecode(clientData));
        try {
            this.data = new ObjectMapper().readTree(rawClientData);
            this.typ = getString(TYPE_PARAM);
            this.challenge = getString(CHALLENGE_PARAM);
            this.origin = getString(ORIGIN_PARAM);
        } catch (IOException ex) {
            throw new BadInputException("Malformed ClientData", ex);
        }
    }

    public String getTyp() {
        return typ;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getOrigin() {
        return origin;
    }

    public String getString(String key) {
        return data.get(key).asText();
    }

    public String getRawClientData() {
        return rawClientData;
    }

    @Override
    public String toString() {
        return rawClientData;
    }
}
