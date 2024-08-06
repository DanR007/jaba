#include "xml.hpp"

#include "../colour.hpp"

#include <iostream>
#include <iterator>
#include <sstream>

XMLParser::XMLParser()
{
	_file_name = "";
}

std::vector<XMLElement> XMLParser::getElements(const std::string& element_name)
{
	std::vector<XMLElement> elements;

	for(XMLElement elem : _elements)
	{
		if(elem.getName() == element_name)
		{
			elements.push_back(elem);
		}
	}
	if(elements.empty())
	{
		std::cout << "Нет такого элемента\n";
	}
	return elements;
}

std::string XMLParser::configureString(const std::string &sender, const std::string &recipient, const std::string &content, const std::string &timestamp)
{
	std::string str = 
	"<message>\n" 
	"<sender content=\"" + sender + "\"></sender>\n"
	"<recipient content=\"" + recipient + "\"></recipient>\n"
	"<data content=\"" + content + "\"></data>\n"
	"<timestamp content=\"" + timestamp + "\"></timestamp>\n"
	"</message>";

	return str;
}

void XMLParser::startReadingFile()
{
    std::ifstream _xml_file;
	_xml_file.open(_file_name);
	std::string str = "";
	while (std::getline(_xml_file, str))
	{
		_full_file.push_back(str);
	}

    auto a = readElement("message");
	std::vector<std::string> elements_name = { "sender", "recipient", "data", "timestamp" };
    for(int i = 0; i < elements_name.size(); ++i)
	{
        readChildElement(elements_name[i], a[0]);
    }
}

void XMLParser::parseXMLStr(const std::string &xml_string)
{
	_elements.clear();
	_full_file.clear();
	
	std::stringstream _xml(xml_string);

	std::string str = "";
	while (std::getline(_xml, str))
	{
		_full_file.push_back(str);
	}

    auto a = readElement("message");
	std::vector<std::string> elements_name = { "sender", "recipient", "data", "timestamp" };
    for(int i = 0; i < elements_name.size(); ++i)
	{
        readChildElement(elements_name[i], a[0]);
    }
}

std::vector<XMLElement> XMLParser::readChildElement(const std::string& name_element, const XMLElement& root_element)
{
	std::vector<XMLElement> xml_elements;
	size_t ind_st;

	for (size_t i = root_element.getStart() + 1; i < root_element.getEnd(); i++)
	{
		size_t ind_end = _full_file[i].find("</" + name_element);
		size_t ind = _full_file[i].find("<"+name_element);
		if (ind != std::string::npos)
        {
			ind_st = i;
        }
		if (ind_end != std::string::npos)
        {
            XMLElement elem = XMLElement(name_element, _full_file[ind_st], ind_st, i);
			xml_elements.push_back(elem);
            _elements.push_back(elem);
        }

	}

	return xml_elements;
}

std::vector<XMLElement> XMLParser::readElement(const std::string& element_name)
{
	std::vector<XMLElement> xml_elements;
	size_t ind_st;
	for (size_t i = 0; i < _full_file.size(); i++)
	{
		size_t ind_end = _full_file[i].find("</" + element_name + '>');
        size_t ind = _full_file[i].find("<" + element_name);

		if (ind != std::string::npos)
        {
			ind_st = i;
        }
		if (ind_end != std::string::npos)
		{
        	XMLElement elem = XMLElement(element_name, _full_file[ind_st], ind_st, i);
			xml_elements.push_back(elem);
            _elements.push_back(elem);
        }
    }
	return xml_elements;
}

XMLAttribute XMLElement::readAttribute(const std::string& attribute_name)
{
	size_t start = _element_line.find(attribute_name + "=\"") + attribute_name.size() + 2, end = _element_line.find("\"", start);
	return attribute_map.emplace(attribute_name, XMLAttribute(_element_line.substr(start, end - start))).first->second;
}

XMLAttribute XMLElement::getAttribute(const std::string& attribute_name)
{
	std::map<std::string, XMLAttribute>::iterator it = attribute_map.find(attribute_name);

	if (it == attribute_map.end())
	{
		std::cerr << RED_BOLD "Can not find attribute with name: " + attribute_name + NONE_FORMAT<< std::endl;
		return XMLAttribute();
	}

	return it->second;
}

XMLAttribute XMLElement::createAttribute(const std::string &attribute_name, const std::string& attribute_data)
{
	XMLAttribute attribute = XMLAttribute();
	attribute.storeData(attribute_data);
    return attribute;
}

XMLElement::XMLElement(const std::string& name, const std::string& element_line, const size_t start_index, const size_t end_index)
{
    _name = name;
	_element_line = element_line;
	_start_line_id = start_index;
	_end_line_id = end_index;
}

XMLAttribute::XMLAttribute(const std::string& attribute)
{
	_attribute_data = attribute;
}
