import "./Home.scss";

import React from "react";
import { Container } from "reactstrap";

import { ContentSection } from "@certego/certego-ui";

import { PUBLIC_URL, VERSION } from "../../constants/environment";

const versionText = VERSION;
// const versionText = "v1.0.0";
const logoBgImg = `url('${PUBLIC_URL}/greedybear.png')`;
const blogPosts = [
  {
    title: "Improvements to GreedyBear",
    subText: "Machine Learning applied to GreedyBear Feeds",
    date: "28th May 2025",
    link: "https://intelowlproject.github.io/blogs/improvements_to_greedybear",
  },
  {
    title: "New project available: GreedyBear",
    subText: "Honeynet Blog: Official announcement",
    date: "27th December 2021",
    link: "https://www.honeynet.org/2021/12/27/new-project-available-greedybear/",
  },
];

function Home() {
  console.debug("Home rendered!");

  return (
    <>
      {/* BG Image */}
      <Container fluid id="home__bgImg" style={{ backgroundImage: logoBgImg }}>
        <h2
          id="home__versionText"
          className="text-accent"
          data-glitch={versionText}
        >
          {versionText}
        </h2>
      </Container>
      {/* Content */}
      <Container id="home__content" className="mt-2">
        <ContentSection className="bg-body shadow lead text-center">
          The project goal is to extract data of the attacks detected by a TPOT
          or a cluster of them and to generate some feeds that can be used to
          prevent and detect attacks.
        </ContentSection>
        <br />
        {/* blogPosts */}
        <h5 className="text-gradient">GreedyBear News</h5>
        <ContentSection>
          {blogPosts.map(({ title, subText, date, link }) => (
            <ContentSection key={title} className="border-dark bg-body">
              <small className="text-muted float-end">{date}</small>
              <h5 className="text-secondary">{title}</h5>
              <p className="mb-2 text-muted">{subText}</p>
              <a
                className="link-ul-primary"
                href={link}
                target="_blank"
                rel="noopener noreferrer"
              >
                Read
              </a>
            </ContentSection>
          ))}
        </ContentSection>
      </Container>
    </>
  );
}

export default Home;
