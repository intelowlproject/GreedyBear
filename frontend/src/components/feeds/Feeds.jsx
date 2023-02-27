import React from "react";
import { 
    Container, 
    Button,
    Col,
    Label,
    //Row,
    FormGroup,
    Spinner,
} from "reactstrap";
import { FEEDS_BASE_URI } from "../../constants/api";
import { 
    ContentSection, 
    useAxiosComponentLoader,
    DataTable,
    Select,
    BooleanIcon,
} from "@certego/certego-ui";
import { Form, Formik } from "formik";

// const FEEDS_ALL_RECENT_URI = `${FEEDS_BASE_URI}/all/all/recent.json`;

const feedTypeChoices = [
    {
        label: "All",
        value: "all",
    },
    {
        label: "Log4j",
        value: "log4j",
    }, 
    {
        label: "Cowrie",
        value: "cowrie",
    },
];

const attackTypeChoices = [
    {
        label: "All",
        value: "all",
    },
    {
        label: "Scanner",
        value: "scanner",
    },
    {
        label: "Payload request",
        value: "payload_request",
    }
];
const ageChoices = [
    {label: "Recent", value: "recent"},
    {label: "Persistant", value: "persistent"}, 
];

const initialValues = {
    feeds_type: "all",
    attack_type: "all",
    age: "recent",
};

export function Feeds(){
    console.debug("Feeds rendered!");

    const columns = [
        {
            Header: "Value",
            accessor: "value",
            maxWidth: 60,
        },
        {
            Header: "Scanner",
            accessor: "scanner",
            Cell: ({ value }) => <BooleanIcon truthy={value} withColors/>,
            maxWidth: 60,
        },
        {
            Header: "Payload Request",
            accessor: "payload_request",
            Cell: ({ value }) => <BooleanIcon truthy={value} withColors/>,
            maxWidth: 60,
        },
        {
            Header: "First Seen",
            accessor: "first_seen",
            maxWidth: 80,
        },
        {
            Header: "Last Seen",
            accessor: "last_seen",
            maxWidth: 80,
        },
        {
            Header: "Times Seen",
            accessor: "times_seen",
            maxWidth: 60,
        },
    ];

    const initialState = {
        pageSize: 20,
    };

    const [url, setUrl] = React.useState(`${FEEDS_BASE_URI}/all/all/recent.json`);

    const onFormSubmit = React.useCallback( (values, formik) => {
        try {
            setUrl(`${FEEDS_BASE_URI}/${values.feeds_type}/${values.attack_type}/${values.age}.json`);
            console.debug(url);
        } catch (e) {
          console.debug(e);
        } finally {
          formik.setSubmitting(false);
        }
    }, [url]);
    
    const [data, Loader] = useAxiosComponentLoader({
        url: url ,
    });

    return(
        <Container>
            <h3 className="fw-bold">Feeds</h3>
            <ContentSection>
                {/* Form */}
            <Formik
                initialValues={initialValues}
                onSubmit={onFormSubmit}
            >
                {(formik) => (
                <Form>
                    {/* username */}
                    <FormGroup row>
                        <Col sm={12} md={3}>
                            <Label
                            className="form-control-label"
                            htmlFor="Feeds__feeds_type"
                            >
                            Feed type:
                            </Label>
                            <Select
                            id="Feeds__feeds_type"
                            name="feeds_type"
                            choices={feedTypeChoices}
                            onChange={formik.handleChange}
                            />
                        </Col>
                        <Col sm={12} md={3}>
                            <Label
                            className="form-control-label"
                            htmlFor="Feeds__attack_type"
                            >
                            Attack type:
                            </Label>
                            <Select
                            id="Feeds__attack_type"
                            name="attack_type"
                            choices={attackTypeChoices}
                            onChange={formik.handleChange}
                            />
                        </Col>
                        <Col sm={12} md={3}>
                            <Label
                            className="form-control-label"
                            htmlFor="Feeds__age"
                            >
                            Age:
                            </Label>
                            <Select
                            id="Feeds__age"
                            name="age"
                            choices={ageChoices}
                            onChange={formik.handleChange}
                            />
                        </Col>
                        <Col sm={12} md={3} className="d-flex align-item-center">
                        <Button
                            type="submit"
                            disabled={formik.isSubmitting}
                            color="primary"
                        >
                            {formik.isSubmitting && <Spinner size="sm" />} Search
                        </Button>
                        </Col>
                    </FormGroup>
                    {/* Submit */}
                    <FormGroup className="d-flex-center">
                        <Button
                            type="submit"
                            disabled={formik.isSubmitting}
                            color="primary"
                        >
                            {formik.isSubmitting && <Spinner size="sm" />} Search
                        </Button>
                    </FormGroup>

                </Form>
                )}
            </Formik>
            </ContentSection>
            <Button
                color="primary"
                outline
                href={url}
                > Raw data
            </Button>
            <ContentSection className="mt-3 bg-dark border border-dark shadow">
                <Loader 
                    render={() => (
                        <DataTable
                            data={data.iocs}
                            columns={columns}
                            config={{
                                enableFilters: true,
                                enableSortBy: false,
                                enableFlexLayout: true,
                            }}
                            initialState={initialState}
                        />
                    )}
                />
            </ContentSection>
        </Container>
    );
}